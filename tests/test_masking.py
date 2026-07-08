"""Backward-compat tests against the original API."""
from pycloak import Anonymizer


def test_fixed_masking():
    a = Anonymizer({"secret": "fixed:hidden"})
    out = a.process_record({"name": "Alice", "secret": "s3cr3t"})
    assert out == {"name": "Alice", "secret": "hidden"}


def test_mask_all_but_last():
    a = Anonymizer({"ssn": "mask_all_but_last_4"})
    out = a.process_record({"ssn": "123-45-6789"})
    assert out["ssn"] == "*******6789"


def test_clear():
    a = Anonymizer({"notes": "clear"})
    out = a.process_record({"notes": "Top Secret"})
    assert out["notes"] is None


def test_faker():
    a = Anonymizer({"email": "faker:email"}, seed=42)
    out = a.process_record({"email": "real@example.com"})
    assert out["email"] != "real@example.com"
    assert "@" in out["email"]
