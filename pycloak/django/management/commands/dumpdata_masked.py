from __future__ import annotations

import json
import sys

from django.apps import apps
from django.conf import settings
from django.core import serializers
from django.core.management.base import BaseCommand, CommandError

from pycloak.anonymizer import Anonymizer
from pycloak.config import load_rules
from pycloak.vault import Vault


class Command(BaseCommand):
    help = (
        "Dump the contents of the database as a fixture, applying py-data-cloak "
        "masking rules. Streams via queryset.iterator() to keep memory bounded."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "args", metavar="app_label[.ModelName]", nargs="*",
            help="Restrict the dump to one or more apps / models.",
        )
        parser.add_argument("--output", "-o", dest="output",
                            help="File to write to (defaults to stdout).")
        parser.add_argument("--indent", type=int, default=None,
                            help="Indent level for pretty-printed JSON.")
        parser.add_argument("--rules", "-r", dest="rules",
                            help="Path to a YAML rules file. Falls back to "
                                 "settings.PY_DATA_CLOAK_MASKING_RULES.")
        parser.add_argument("--chunk-size", type=int, default=2000,
                            help="Batch size for queryset.iterator() (default 2000).")
        parser.add_argument("--seed", type=int, default=None,
                            help="RNG seed for reproducible output.")
        parser.add_argument("--locale", default=None, help="Faker locale, e.g. en_US.")
        parser.add_argument("--vault", dest="vault_path", default=None,
                            help="Persistent vault path for cross-run consistency.")
        parser.add_argument("--vault-key", dest="vault_key", default=None,
                            help="Passphrase for an encrypted vault.")

    def handle(self, *app_labels, **options):
        rules_path = options.get("rules")
        rules = load_rules(rules_path) if rules_path else getattr(settings, "PY_DATA_CLOAK_MASKING_RULES", {})
        if isinstance(rules, str):
            rules = load_rules(rules)
        if not rules:
            self.stdout.write(self.style.WARNING(
                "No masking rules configured; data will be dumped unchanged."
            ))

        vault = Vault(options["vault_path"], passphrase=options.get("vault_key")) \
            if options.get("vault_path") else None

        anonymizer = Anonymizer(
            rules,
            seed=options.get("seed"),
            locale=options.get("locale"),
            vault=vault,
        )

        models = self._resolve_models(app_labels)
        chunk_size = options["chunk_size"]
        indent = options.get("indent")
        output_path = options.get("output")

        out_fp = open(output_path, "w", encoding="utf-8") if output_path else self.stdout
        try:
            out_fp.write("[")
            first = True
            total = 0
            for model in models:
                qs = model._default_manager.all()
                for obj in qs.iterator(chunk_size=chunk_size):
                    item = serializers.serialize("python", [obj])[0]
                    item["fields"] = anonymizer.process_record(item["fields"])
                    sep = "" if first else ","
                    if indent is not None:
                        out_fp.write(sep + "\n" + json.dumps(item, indent=indent, default=str))
                    else:
                        out_fp.write(sep + json.dumps(item, default=str))
                    first = False
                    total += 1
            out_fp.write("\n]" if indent is not None else "]")
            out_fp.write("\n")
        finally:
            if output_path:
                out_fp.close()

        if vault is not None:
            anonymizer.save()

        self.stderr.write(self.style.SUCCESS(f"Dumped {total} record(s)."))

    def _resolve_models(self, app_labels):
        if not app_labels:
            models = []
            for cfg in apps.get_app_configs():
                models.extend(cfg.get_models())
            return models

        models = []
        for label in app_labels:
            try:
                if "." in label:
                    models.append(apps.get_model(label))
                else:
                    models.extend(apps.get_app_config(label).get_models())
            except LookupError as e:
                raise CommandError(str(e)) from e
        return models
