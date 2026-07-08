from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import yaml

from .exceptions import FormatError
from .rules import parse_rule


def load_rules(path: str) -> Dict[str, str]:
    """Load a YAML rules file. Returns a dict; empty file -> empty dict."""
    p = Path(path)
    with p.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise FormatError(f"Rules file {path!r} must contain a YAML mapping at the top level.")
    return data


def validate_rules(rules: Dict[str, Any]) -> None:
    """Parse every rule spec to surface errors early. Raises on first bad rule."""
    for field, spec in rules.items():
        if not isinstance(field, str):
            raise FormatError(f"Rule field must be a string, got {type(field).__name__}: {field!r}")
        parse_rule(spec)
