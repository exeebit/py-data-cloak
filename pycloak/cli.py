import click
import json
import csv
import sys
from .masking import Anonymizer, load_rules

@click.group()
def main():
    """py-data-cloak: Data anonymization tool."""
    pass

@main.command()
@click.argument('input_file', type=click.File('r'))
@click.option('--rules', '-r', type=click.Path(exists=True), required=True, help='Path to masking rules (YAML).')
@click.option('--output', '-o', type=click.File('w'), default='-', help='Output file (defaults to stdout).')
@click.option('--format', '-f', type=click.Choice(['json', 'csv']), default=None, help='Input format. Auto-detected if ignored.')
def process(input_file, rules, output, format):
    """Process a file (JSON or CSV) and apply masking rules."""
    
    # Simple format detection
    if not format:
        if input_file.name.endswith('.csv'):
            format = 'csv'
        else:
            format = 'json'

    # Load rules
    try:
        rule_dict = load_rules(rules)
    except Exception as e:
        click.echo(f"Error loading rules: {e}", err=True)
        sys.exit(1)

    anonymizer = Anonymizer(rule_dict)

    if format == 'json':
        try:
            data = json.load(input_file)
            if isinstance(data, list):
                processed_data = [anonymizer.process_record(item) for item in data]
            elif isinstance(data, dict):
                processed_data = anonymizer.process_record(data)
            else:
                click.echo("Error: JSON root must be list or dict", err=True)
                sys.exit(1)
            
            json.dump(processed_data, output, indent=2)
        except json.JSONDecodeError as e:
            click.echo(f"Invalid JSON: {e}", err=True)
            sys.exit(1)

    elif format == 'csv':
        reader = csv.DictReader(input_file)
        if not reader.fieldnames:
            click.echo("Error: CSV must have header row", err=True)
            sys.exit(1)
            
        writer = csv.DictWriter(output, fieldnames=reader.fieldnames)
        writer.writeheader()
        
        for row in reader:
            writer.writerow(anonymizer.process_record(row))

if __name__ == '__main__':
    main()
