"""Field-name matching: exact, glob, regex, and dotted nested paths.

A rules dict maps a field pattern -> a rule spec string. Patterns are
classified as:

    exact          "email", "user.address.street"
    glob           "*_email", "user.*"
    regex          "re:^.*_id$"

Exact patterns are checked first (fastest). For misses, glob and regex
patterns are scanned in the order they were declared, so users can put more
specific patterns before broader catch-alls.
"""
from __future__ import annotations

import fnmatch
import re
from typing import Dict, Iterable, List, Optional, Tuple

from .rules import Rule, parse_rule


_GLOB_CHARS = set("*?[")


def _is_glob(pattern: str) -> bool:
    return any(c in pattern for c in _GLOB_CHARS)


class FieldMatcher:
    """Resolve a field name (possibly dotted, like "user.email") to a Rule."""

    def __init__(self, rules: Dict[str, object]):
        self._exact: Dict[str, Tuple[str, Rule]] = {}
        self._patterns: List[Tuple[object, str, Rule, str]] = []
        self._cache: Dict[str, Optional[Tuple[str, Rule]]] = {}

        for pattern, spec in rules.items():
            rule = parse_rule(spec)
            spec_str = rule.spec if isinstance(spec, Rule) else spec
            if pattern.startswith("re:"):
                self._patterns.append((re.compile(pattern[3:]), spec_str, rule, "regex"))
            elif _is_glob(pattern):
                self._patterns.append((pattern, spec_str, rule, "glob"))
            else:
                self._exact[pattern] = (spec_str, rule)

    def find(self, field_name: str) -> Optional[Tuple[str, Rule]]:
        """Return (spec_string, Rule) or None if no rule matches.

        Matching order:
          1. Exact dotted path  ("user.email" → rule "user.email")
          2. Leaf fallback      ("user.email" → rule "email", only if rule
                                  key has no dots)
          3. Glob / regex patterns in declaration order
        """
        if field_name in self._cache:
            return self._cache[field_name]

        hit: Optional[Tuple[str, Rule]] = self._exact.get(field_name)
        if hit is None and "." in field_name:
            leaf = field_name.rsplit(".", 1)[-1]
            hit = self._exact.get(leaf)
        if hit is None:
            for pattern, spec_str, rule, kind in self._patterns:
                if kind == "glob":
                    if fnmatch.fnmatchcase(field_name, pattern):
                        hit = (spec_str, rule)
                        break
                else:  # regex
                    if pattern.search(field_name):
                        hit = (spec_str, rule)
                        break

        self._cache[field_name] = hit
        return hit

    def field_names(self) -> Iterable[str]:
        """Yield exact field names declared in the rules (used for scan/report)."""
        return self._exact.keys()
