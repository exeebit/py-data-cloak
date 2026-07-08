from __future__ import annotations

import json
import sys
from pathlib import Path

import click
import yaml

from . import __version__
from .anonymizer import Anonymizer
from .config import load_rules, validate_rules
from .detect import detect_rules
from .exceptions import PycloakError
from .formats import detect_format, process_csv, process_json, process_ndjson, process_sql
from .vault import Vault


@click.group()
@click.version_option(__version__, prog_name="pycloak")
def main():
    """py-data-cloak: rule-based data anonymization."""


# ---------------------------------------------------------------- process

@main.command()
@click.argument("input_path", type=click.Path(exists=True, dir_okay=False, allow_dash=True))
@click.option("--rules", "-r", "rules_path", type=click.Path(exists=True), required=True,
              help="Path to masking rules (YAML).")
@click.option("--output", "-o", "output_path", type=click.Path(allow_dash=True), default="-",
              help="Output file (default: stdout).")
@click.option("--format", "-f", "fmt",
              type=click.Choice(["json", "ndjson", "csv", "sql"]),
              default=None,
              help="Input format. Auto-detected by extension when omitted.")
@click.option("--seed", type=int, default=None, help="RNG seed for reproducible output.")
@click.option("--locale", "locale", default=None, help="Faker locale, e.g. en_US, de_DE.")
@click.option("--vault", "vault_path", type=click.Path(), default=None,
              help="Path to a persistent vault for cross-run consistency.")
@click.option("--vault-key", "vault_key", default=None,
              help="Passphrase to encrypt/decrypt the vault.")
@click.option("--no-consistency", is_flag=True, default=False,
              help="Disable in-session consistency cache.")
@click.option("--dry-run", is_flag=True, default=False,
              help="Print what would be masked, write no output.")
@click.option("--indent", type=int, default=2, show_default=True,
              help="Indent for JSON output.")
def process(input_path, rules_path, output_path, fmt, seed, locale, vault_path, vault_key,
            no_consistency, dry_run, indent):
    """Mask a file (JSON, NDJSON, CSV, or SQL dump) using rules."""
    try:
        rules = load_rules(rules_path)
        validate_rules(rules)
    except PycloakError as e:
        raise click.ClickException(str(e))

    vault = None
    if vault_path:
        vault = Vault(vault_path, passphrase=vault_key)

    anonymizer = Anonymizer(
        rules,
        seed=seed,
        locale=locale,
        consistent=not no_consistency,
        vault=vault,
    )

    if fmt is None:
        fmt = "json" if input_path == "-" else detect_format(input_path)

    if dry_run:
        _do_dry_run(input_path, fmt, anonymizer)
        return

    in_f = click.get_text_stream("stdin") if input_path == "-" else open(input_path, "r", encoding="utf-8")
    out_f = click.get_text_stream("stdout") if output_path == "-" else open(output_path, "w", encoding="utf-8")
    try:
        try:
            if fmt == "json":
                count = process_json(in_f, out_f, anonymizer, indent=indent)
            elif fmt == "ndjson":
                count = process_ndjson(in_f, out_f, anonymizer)
            elif fmt == "csv":
                count = process_csv(in_f, out_f, anonymizer)
            elif fmt == "sql":
                count = process_sql(in_f, out_f, anonymizer)
            else:
                raise click.ClickException(f"Unsupported format: {fmt}")
        except PycloakError as e:
            raise click.ClickException(str(e))
    finally:
        if input_path != "-":
            in_f.close()
        if output_path != "-":
            out_f.close()

    if vault is not None:
        anonymizer.save()

    click.echo(f"Masked {count} record(s).", err=True)


def _do_dry_run(input_path, fmt, anonymizer):
    """Read up to 100 records and print a per-field change summary."""
    if input_path == "-":
        raise click.ClickException("--dry-run requires a file path (not stdin)")
    records = list(_iter_records_for_preview(input_path, fmt, limit=100))
    if not records:
        click.echo("No records found.", err=True)
        return

    fields = set()
    for r in records:
        if isinstance(r, dict):
            fields.update(_flat_keys(r))

    rows = []
    for field in sorted(fields):
        match = anonymizer.matcher.find(field)
        if match is None:
            rows.append((field, "(no rule)", "", ""))
            continue
        spec, _ = match
        # find a sample value
        sample = None
        for r in records:
            v = _get_path(r, field)
            if v is not None:
                sample = v
                break
        masked = anonymizer.mask_value(field, sample) if sample is not None else None
        rows.append((field, spec, _trunc(sample), _trunc(masked)))

    width_f = max(len(r[0]) for r in rows)
    width_r = max(len(r[1]) for r in rows)
    click.echo(f"{'FIELD'.ljust(width_f)}  {'RULE'.ljust(width_r)}  ORIGINAL -> MASKED")
    click.echo(f"{'-' * width_f}  {'-' * width_r}  ------------------")
    for field, spec, original, masked in rows:
        if spec == "(no rule)":
            click.echo(f"{field.ljust(width_f)}  {spec.ljust(width_r)}  (unchanged)")
        else:
            click.echo(f"{field.ljust(width_f)}  {spec.ljust(width_r)}  {original} -> {masked}")


def _iter_records_for_preview(path, fmt, limit):
    with open(path, "r", encoding="utf-8") as f:
        if fmt == "json":
            data = json.load(f)
            if isinstance(data, list):
                for item in data[:limit]:
                    if isinstance(item, dict):
                        yield item
            elif isinstance(data, dict):
                yield data
        elif fmt == "ndjson":
            for i, line in enumerate(f):
                if i >= limit:
                    break
                line = line.strip()
                if line:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        yield obj
        elif fmt == "csv":
            import csv as _csv
            for i, row in enumerate(_csv.DictReader(f)):
                if i >= limit:
                    break
                yield row
        elif fmt == "sql":
            # crude: pull one INSERT for preview
            click.echo("(SQL dry-run shows fields from the first INSERT only)", err=True)


def _flat_keys(d, prefix=""):
    if isinstance(d, dict):
        for k, v in d.items():
            new_prefix = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict):
                yield from _flat_keys(v, new_prefix)
            else:
                yield new_prefix


def _get_path(d, path):
    for part in path.split("."):
        if not isinstance(d, dict):
            return None
        d = d.get(part)
        if d is None:
            return None
    return d


def _trunc(v, n=40):
    s = str(v)
    return s if len(s) <= n else s[: n - 1] + "..."


# ---------------------------------------------------------------- scan

@main.command()
@click.argument("input_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--format", "-f", "fmt",
              type=click.Choice(["json", "ndjson", "csv"]),
              default=None,
              help="Input format. Auto-detected by extension when omitted.")
@click.option("--output", "-o", "output_path", type=click.Path(), default=None,
              help="Write suggested rules to this file (default: stdout).")
@click.option("--sample", "sample_size", type=int, default=500, show_default=True,
              help="Number of records to sample for detection.")
def scan(input_path, fmt, output_path, sample_size):
    """Scan a file and emit a starter rules YAML based on detected PII."""
    if fmt is None:
        fmt = detect_format(input_path)

    records = list(_iter_records_for_preview(input_path, fmt, limit=sample_size))
    if not records:
        raise click.ClickException("No records found to scan.")

    suggestions = detect_rules(records, sample_size=sample_size)
    if not suggestions:
        click.echo("# No PII detected.", err=True)
        rendered = "# No fields matched.\n"
    else:
        rendered = "# Auto-detected by `pycloak scan` — review before using.\n"
        rendered += yaml.safe_dump(suggestions, sort_keys=True, default_flow_style=False)

    if output_path:
        Path(output_path).write_text(rendered, encoding="utf-8")
        click.echo(f"Wrote {len(suggestions)} suggestion(s) to {output_path}", err=True)
    else:
        click.echo(rendered)


if __name__ == "__main__":
    main()
