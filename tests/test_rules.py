"""Tests for individual rule handlers."""
import datetime as dt
import hashlib

import pytest

from pycloak import Anonymizer
from pycloak.exceptions import InvalidRuleError, UnknownRuleError
from pycloak.rules import parse_rule


# --- parsing ------------------------------------------------------------------

def test_unknown_rule_raises():
    with pytest.raises(UnknownRuleError):
        parse_rule("not_a_real_rule")


def test_rule_must_be_string():
    with pytest.raises(InvalidRuleError):
        parse_rule(42)


# --- redact -------------------------------------------------------------------

def test_redact_default():
    a = Anonymizer({"x": "redact"})
    assert a.process_record({"x": "anything"})["x"] == "[REDACTED]"


def test_redact_custom():
    a = Anonymizer({"x": "redact:HIDDEN"})
    assert a.process_record({"x": "anything"})["x"] == "HIDDEN"


# --- partial ------------------------------------------------------------------

def test_partial_keeps_ends():
    a = Anonymizer({"email": "partial:1:8"})
    out = a.process_record({"email": "alice@example.com"})
    assert out["email"].startswith("a")
    assert out["email"].endswith("mple.com")
    assert "*" in out["email"]


def test_partial_short_input_unchanged():
    a = Anonymizer({"x": "partial:2:2"})
    assert a.process_record({"x": "ab"})["x"] == "ab"


def test_partial_requires_two_ints():
    with pytest.raises(InvalidRuleError):
        parse_rule("partial:abc:1")


# --- format_preserve ----------------------------------------------------------

def test_format_preserve_keeps_shape():
    a = Anonymizer({"phone": "format_preserve"}, seed=1)
    out = a.process_record({"phone": "555-123-4567"})
    masked = out["phone"]
    assert masked != "555-123-4567"
    assert masked[3] == "-" and masked[7] == "-"
    assert all(c.isdigit() for c in masked.replace("-", ""))


def test_format_preserve_letters_case():
    a = Anonymizer({"id": "format_preserve"}, seed=1)
    out = a.process_record({"id": "ABC-xyz-123"})
    m = out["id"]
    assert m[:3].isupper() and m[:3].isalpha()
    assert m[4:7].islower() and m[4:7].isalpha()
    assert m[8:].isdigit()


def test_format_preserve_luhn():
    a = Anonymizer({"cc": "format_preserve:luhn"}, seed=1)
    out = a.process_record({"cc": "4532-1488-0343-6467"})
    masked_digits = [int(c) for c in out["cc"] if c.isdigit()]
    # Luhn-validate
    total = 0
    for i, d in enumerate(reversed(masked_digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    assert total % 10 == 0


# --- hash ---------------------------------------------------------------------

def test_hash_default_sha256():
    a = Anonymizer({"id": "hash"})
    out = a.process_record({"id": "user-42"})
    expected = hashlib.sha256(b"user-42").hexdigest()
    assert out["id"] == expected


def test_hash_with_salt_is_deterministic():
    a = Anonymizer({"id": "hash:sha256:pepper"})
    out1 = a.process_record({"id": "user-42"})
    out2 = a.process_record({"id": "user-42"})
    assert out1["id"] == out2["id"]
    expected = hashlib.sha256(b"pepperuser-42").hexdigest()
    assert out1["id"] == expected


def test_hash_unknown_algo():
    with pytest.raises(InvalidRuleError):
        parse_rule("hash:notarealalgo")


# --- noise --------------------------------------------------------------------

def test_noise_modifies_numeric_value():
    a = Anonymizer({"salary": "noise:1000"}, seed=1, consistent=False)
    out = a.process_record({"salary": 50000})
    assert out["salary"] != 50000
    assert isinstance(out["salary"], int)


def test_noise_preserves_float_type():
    a = Anonymizer({"x": "noise:0.5"}, seed=1, consistent=False)
    out = a.process_record({"x": 1.5})
    assert isinstance(out["x"], float)


def test_noise_passes_through_non_numeric():
    a = Anonymizer({"x": "noise:1"})
    out = a.process_record({"x": "not-a-number"})
    assert out["x"] == "not-a-number"


# --- shift_date ---------------------------------------------------------------

def test_shift_date_string():
    a = Anonymizer({"dob": "shift_date:30"}, seed=1)
    out = a.process_record({"dob": "1990-01-15"})
    assert out["dob"] != "1990-01-15"
    # Should still parse as a date
    parsed = dt.date.fromisoformat(out["dob"])
    delta = abs((parsed - dt.date(1990, 1, 15)).days)
    assert delta <= 30


def test_shift_date_datetime_object():
    a = Anonymizer({"ts": "shift_date:7"}, seed=1)
    out = a.process_record({"ts": dt.datetime(2024, 3, 1, 12, 0)})
    assert isinstance(out["ts"], dt.datetime)
    delta = abs((out["ts"] - dt.datetime(2024, 3, 1, 12, 0)).days)
    assert delta <= 7


def test_shift_date_bad_input_passes_through():
    a = Anonymizer({"d": "shift_date:30"})
    assert a.process_record({"d": "not-a-date"})["d"] == "not-a-date"


def test_shift_date_needs_positive_days():
    with pytest.raises(InvalidRuleError):
        parse_rule("shift_date:0")


# --- custom -------------------------------------------------------------------

def test_custom_rule(tmp_path, monkeypatch):
    # Build a tiny module on disk and put it on sys.path
    mod_dir = tmp_path / "custmod"
    mod_dir.mkdir()
    (mod_dir / "__init__.py").write_text("")
    (mod_dir / "thing.py").write_text(
        "def upper(v, ctx):\n    return str(v).upper()\n"
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    a = Anonymizer({"name": "custom:custmod.thing:upper"})
    out = a.process_record({"name": "alice"})
    assert out["name"] == "ALICE"


# --- faker --------------------------------------------------------------------

def test_faker_unknown_provider_raises():
    a = Anonymizer({"x": "faker:does_not_exist"})
    with pytest.raises(InvalidRuleError):
        a.process_record({"x": "anything"})


def test_faker_with_args():
    a = Anonymizer({"pw": "faker:password:12"}, seed=1)
    out = a.process_record({"pw": "old"})
    assert len(out["pw"]) == 12


# --- null handling ------------------------------------------------------------

def test_null_passes_through():
    a = Anonymizer({"email": "faker:email"})
    out = a.process_record({"email": None})
    assert out["email"] is None
