import yaml
import json
import csv
import sys
from typing import Dict, Any, Callable, Optional
from faker import Faker

fake = Faker()

class Anonymizer:
    def __init__(self, rules: Dict[str, str], seed: int = None):
        self.rules = rules
        if seed:
            Faker.seed(seed)
        self._cache = {}  # For consistency if needed (not fully implemented for all fields to save memory, but could be)

    def mask_value(self, field_name: str, value: Any) -> Any:
        rule = self.rules.get(field_name)
        if not rule:
            return value
        
        if value is None:
            return None

        # consistency check could go here if we want strict referential integrity for specific fields
        
        if rule.startswith("faker:"):
            provider = rule.split(":", 1)[1]
            try:
                return getattr(fake, provider)()
            except AttributeError:
                return f"<Invalid Faker Provider: {provider}>"
        
        if rule.startswith("fixed:"):
            return rule.split(":", 1)[1]
        
        if rule == "clear":
            return None
        
        if rule.startswith("mask_all_but_last_"):
            try:
                n = int(rule.split("mask_all_but_last_")[1])
                str_val = str(value)
                if len(str_val) <= n:
                    return str_val
                return "*" * (len(str_val) - n) + str_val[-n:]
            except ValueError:
                return value

        return value

    def process_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Process a single dictionary record (row)."""
        new_record = {}
        for k, v in record.items():
            new_record[k] = self.mask_value(k, v)
        return new_record

def load_rules(path: str) -> Dict[str, str]:
    with open(path, 'r') as f:
        return yaml.safe_load(f) or {}
