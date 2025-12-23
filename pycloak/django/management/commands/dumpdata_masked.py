import json
from django.core.management.base import BaseCommand, CommandError
from django.core import serializers
from django.apps import apps
from django.conf import settings
from pycloak.masking import Anonymizer, load_rules

class Command(BaseCommand):
    help = 'Output the contents of the database as a fixture of the given format (using masking rules).'

    def add_arguments(self, parser):
        parser.add_argument('args', metavar='app_label.ModelName', nargs='*',
            help='Restricts dumped data to the specified app_label or app_label.ModelName.')
        parser.add_argument('--output', '-o', dest='output',
            help='Specifies file to which the output is written.')
        parser.add_argument('--indent', type=int, default=None,
            help='Specifies the indent level to use when pretty-printing output.')
        parser.add_argument('--rules', '-r', dest='rules',
            help='Path to masking rules YAML file. Defaults to settings.PY_DATA_CLOAK_MASKING_RULES.')

    def handle(self, *app_labels, **options):
        rules_path = options.get('rules')
        if rules_path:
            rules = load_rules(rules_path)
        else:
            rules = getattr(settings, 'PY_DATA_CLOAK_MASKING_RULES', {})

        if not rules:
            self.stdout.write(self.style.WARNING("No masking rules found. Data will be dumped raw if fields don't match rules (or empty rules)."))

        anonymizer = Anonymizer(rules)
        
        # Get models to dump
        models = []
        if len(app_labels) == 0:
            # Dump all (simplified, usually dumpdata handles this complex logic better, 
            # here we assume user passes specific models or we might iterate all installed apps)
            for app_config in apps.get_app_configs():
                models.extend(app_config.get_models())
        else:
            for label in app_labels:
                try:
                    if '.' in label:
                        models.append(apps.get_model(label))
                    else:
                        app_config = apps.get_app_config(label)
                        models.extend(app_config.get_models())
                except LookupError:
                    raise CommandError(f"Unknown model or app: {label}")

        objects = []
        for model in models:
            for obj in model.objects.all():
                objects.append(obj)

        # We need to hook into the serialization process to mask *before* it produces the final JSON.
        # Django's serializer isn't easily stream-modifiable for fields *inside* the serialized output without
        # deserializing or subclassing the serializer. 
        # Easier approach: Use python serializer to get dicts, modify dicts, then dump to JSON.
        
        # 1. Serialize to python objects (list of dicts)
        data = serializers.serialize('python', objects)
        
        # 2. Apply masking
        masked_data = []
        for item in data:
            # item is {'model': '...', 'pk': '...', 'fields': {...}}
            fields = item['fields']
            new_fields = anonymizer.process_record(fields)
            item['fields'] = new_fields
            masked_data.append(item)

        # 3. Dump to JSON (or other format, supporting JSON for now)
        output = options.get('output')
        
        if output:
            with open(output, 'w') as f:
                json.dump(masked_data, f, indent=options.get('indent'), default=str)
        else:
            self.stdout.write(json.dumps(masked_data, indent=options.get('indent'), default=str))
