from __future__ import annotations

import random
from typing import Any, Callable, Dict, Iterable, Iterator, Optional

from faker import Faker

from .matching import FieldMatcher
from .rules import Rule, RuleContext


class Anonymizer:
    """Apply masking rules to records.

    Parameters
    ----------
    rules:
        Mapping of field pattern -> rule spec (or :class:`Rule` instance).
    seed:
        Seed for the RNG and Faker. Same seed + same rules + same input -> same output.
    locale:
        Faker locale, e.g. 'en_US', 'de_DE'. Defaults to Faker's default.
    consistent:
        When True (default), the same (rule, input) pair always produces the
        same output within this Anonymizer's lifetime. Set False to make
        every call independently random.
    vault:
        Optional :class:`pycloak.vault.Vault`. If provided, the consistency
        cache is loaded from / persisted to the vault, giving cross-session
        consistency.
    """

    def __init__(
        self,
        rules: Optional[Dict[str, Any]] = None,
        *,
        seed: Optional[int] = None,
        locale: Optional[str] = None,
        consistent: bool = True,
        vault: Optional["pycloak.vault.Vault"] = None,  # type: ignore[name-defined]
    ):
        self.rules = rules or {}
        self.matcher = FieldMatcher(self.rules)
        self.faker = Faker(locale) if locale else Faker()
        self.consistent = consistent
        self.vault = vault
        self._cache: Dict[tuple, Any] = {}
        if seed is not None:
            Faker.seed(seed)
            self.faker.seed_instance(seed)
            self._rng = random.Random(seed)
        else:
            self._rng = random.Random()

        if vault is not None:
            self._cache.update(vault.load())

    # ------------------------------------------------------------------ core

    def mask_value(self, field_name: str, value: Any) -> Any:
        """Apply the matching rule to a single value. No-op if no rule matches."""
        if value is None:
            return None
        match = self.matcher.find(field_name)
        if match is None:
            return value
        spec_str, rule = match
        if self.consistent:
            key = (spec_str, _cache_key(value))
            if key in self._cache:
                return self._cache[key]
            masked = rule.apply(value, self._ctx(field_name))
            self._cache[key] = masked
            return masked
        return rule.apply(value, self._ctx(field_name))

    def process_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Walk a record (possibly nested) and mask matching leaves."""
        return self._walk(record, "")

    def process_records(self, records: Iterable[Dict[str, Any]]) -> Iterator[Dict[str, Any]]:
        """Stream-friendly: yields masked records one at a time."""
        for r in records:
            yield self.process_record(r)

    # ------------------------------------------------------------------ helpers

    def _ctx(self, field_name: str) -> RuleContext:
        return RuleContext(faker=self.faker, rng=self._rng, field_name=field_name)

    def _walk(self, value: Any, path: str) -> Any:
        if isinstance(value, dict):
            return {k: self._walk(v, _join(path, k)) for k, v in value.items()}
        if isinstance(value, list):
            return [self._walk(item, path) for item in value]
        return self.mask_value(path, value)

    # ------------------------------------------------------------------ vault

    def save(self) -> None:
        """Persist the consistency cache to the vault (if one was provided)."""
        if self.vault is not None:
            self.vault.save(self._cache)


def _join(prefix: str, key: str) -> str:
    return f"{prefix}.{key}" if prefix else key


def _cache_key(value: Any):
    """Return a hashable, stable cache key for any value."""
    try:
        hash(value)
        return value
    except TypeError:
        return repr(value)
