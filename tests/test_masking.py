import pytest
from pycloak.masking import Anonymizer

def test_fixed_masking():
    rules = {"secret": "fixed:hidden"}
    anonymizer = Anonymizer(rules)
    data = {"name": "Alice", "secret": "s3cr3t"}
    result = anonymizer.process_record(data)
    assert result["name"] == "Alice"
    assert result["secret"] == "hidden"

def test_mask_all_but_last():
    rules = {"ssn": "mask_all_but_last_4"}
    anonymizer = Anonymizer(rules)
    data = {"ssn": "123-45-6789"}
    result = anonymizer.process_record(data)
    assert result["ssn"] == "*******6789"

def test_clear():
    rules = {"notes": "clear"}
    anonymizer = Anonymizer(rules)
    data = {"notes": "Top Secret"}
    result = anonymizer.process_record(data)
    assert result["notes"] is None

def test_faker():
    rules = {"email": "faker:email"}
    anonymizer = Anonymizer(rules, seed=42)
    data = {"email": "real@example.com"}
    result = anonymizer.process_record(data)
    assert result["email"] != "real@example.com"
    assert "@" in result["email"]
