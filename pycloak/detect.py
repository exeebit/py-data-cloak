"""PII auto-detection: scan sample data and suggest masking rules.

Two signals are combined:

1.  **Name signals** — fuzzy matches on column names (e.g. "user_email" suggests
    a mail rule, "ssn" suggests a Social Security mask).
2.  **Value signals** — regex/Luhn checks on a sample of values
    (e.g. a column where >50% of values look like emails).

The output is an ordered dict { field_name: rule_spec }, suitable for
dumping to YAML and editing by hand.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional


@dataclass(frozen=True)
class Detector:
    name: str             # column-name keyword
    name_score: float     # weight for name match (0-1)
    value_re: Optional[re.Pattern]
    value_score: float    # weight for value match
    rule: str             # suggested rule spec
    extra_check: Optional[str] = None  # 'luhn' for credit cards


_EMAIL_RE = re.compile(r"^[\w.+-]+@[\w-]+(?:\.[\w-]+)+$")
_SSN_RE = re.compile(r"^\d{3}-?\d{2}-?\d{4}$")
_PHONE_RE = re.compile(r"^\+?[\d\s().-]{7,}$")
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+$")
_CREDIT_RE = re.compile(r"^[\d\s-]{13,23}$")
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2})?")


DETECTORS: List[Detector] = [
    Detector("email", 0.9, _EMAIL_RE, 0.95, "faker:email"),
    Detector("e_mail", 0.9, _EMAIL_RE, 0.95, "faker:email"),
    Detector("mail", 0.6, _EMAIL_RE, 0.95, "faker:email"),
    Detector("ssn", 0.95, _SSN_RE, 0.9, "mask_all_but_last_4"),
    Detector("social_security", 0.95, _SSN_RE, 0.9, "mask_all_but_last_4"),
    Detector("phone", 0.85, _PHONE_RE, 0.6, "format_preserve"),
    Detector("mobile", 0.85, _PHONE_RE, 0.6, "format_preserve"),
    Detector("tel", 0.7, _PHONE_RE, 0.6, "format_preserve"),
    Detector("credit_card", 0.95, _CREDIT_RE, 0.9, "format_preserve:luhn", extra_check="luhn"),
    Detector("cc_number", 0.95, _CREDIT_RE, 0.9, "format_preserve:luhn", extra_check="luhn"),
    Detector("card_number", 0.9, _CREDIT_RE, 0.9, "format_preserve:luhn", extra_check="luhn"),
    Detector("ip", 0.85, _IPV4_RE, 0.9, "faker:ipv4"),
    Detector("ip_address", 0.95, _IPV4_RE, 0.9, "faker:ipv4"),
    Detector("first_name", 0.95, None, 0.0, "faker:first_name"),
    Detector("last_name", 0.95, None, 0.0, "faker:last_name"),
    Detector("full_name", 0.95, None, 0.0, "faker:name"),
    Detector("name", 0.5, None, 0.0, "faker:name"),
    Detector("address", 0.85, None, 0.0, "faker:address"),
    Detector("street", 0.8, None, 0.0, "faker:street_address"),
    Detector("city", 0.8, None, 0.0, "faker:city"),
    Detector("zip", 0.8, None, 0.0, "faker:postcode"),
    Detector("postcode", 0.85, None, 0.0, "faker:postcode"),
    Detector("country", 0.7, None, 0.0, "faker:country"),
    Detector("dob", 0.95, _DATE_RE, 0.7, "shift_date:365"),
    Detector("birth", 0.85, _DATE_RE, 0.7, "shift_date:365"),
    Detector("date_of_birth", 0.95, _DATE_RE, 0.7, "shift_date:365"),
    Detector("password", 0.95, None, 0.0, "fixed:***REDACTED***"),
    Detector("secret", 0.85, None, 0.0, "redact"),
    Detector("token", 0.7, None, 0.0, "hash:sha256"),
    Detector("api_key", 0.95, None, 0.0, "hash:sha256"),
    Detector("url", 0.6, _URL_RE, 0.7, "faker:url"),
    Detector("user_agent", 0.9, None, 0.0, "faker:user_agent"),
]


def _luhn_valid(num_str: str) -> bool:
    digits = [int(c) for c in num_str if c.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _name_score(field: str, keyword: str) -> float:
    """Soft match: substring, with bonus for exact / boundary match."""
    f = field.lower()
    k = keyword.lower()
    if f == k:
        return 1.0
    if k in f.split("_"):
        return 0.95
    if k in f:
        return 0.7
    return 0.0


def _value_hit_ratio(values: List[Any], pattern: re.Pattern, extra_check: Optional[str]) -> float:
    if not values:
        return 0.0
    non_null = [str(v) for v in values if v is not None and str(v).strip() != ""]
    if not non_null:
        return 0.0
    hits = 0
    for v in non_null:
        if not pattern.match(v):
            continue
        if extra_check == "luhn" and not _luhn_valid(v):
            continue
        hits += 1
    return hits / len(non_null)


def detect_rules(records: Iterable[Dict[str, Any]], sample_size: int = 500) -> Dict[str, str]:
    """Inspect a sample of records and return a suggested {field: rule} map.

    Only fields with detector confidence >= 0.5 are included.
    """
    samples: Dict[str, List[Any]] = defaultdict(list)
    seen = 0
    for record in records:
        if not isinstance(record, dict):
            continue
        for k, v in record.items():
            if isinstance(k, str):
                samples[k].append(v)
        seen += 1
        if seen >= sample_size:
            break

    suggestions: Dict[str, str] = {}
    for field, values in samples.items():
        best_rule = None
        best_score = 0.0
        for det in DETECTORS:
            name_match = _name_score(field, det.name)
            value_match = 0.0
            if det.value_re is not None:
                value_match = _value_hit_ratio(values, det.value_re, det.extra_check)
            # Combine: high value match overrides a weak name match; high name match
            # is enough on its own.
            score = max(
                name_match * det.name_score,
                value_match * det.value_score,
                # name + value combined gives a boost
                (name_match * 0.6 + value_match * 0.6) if value_match > 0 else 0,
            )
            if score > best_score:
                best_score = score
                best_rule = det.rule
        if best_rule is not None and best_score >= 0.5:
            suggestions[field] = best_rule
    return suggestions
