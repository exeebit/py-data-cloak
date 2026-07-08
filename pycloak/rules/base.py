from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from faker import Faker


@dataclass
class RuleContext:
    """Per-call context passed to Rule.apply()."""
    faker: "Faker"
    rng: random.Random
    field_name: str


class Rule:
    """Base class for all masking rules.

    Subclasses implement matches() and parse() as classmethods, and apply()
    as an instance method. Register subclasses with @register_rule.
    """

    spec: str = ""

    @classmethod
    def matches(cls, spec: str) -> bool:
        raise NotImplementedError

    @classmethod
    def parse(cls, spec: str) -> "Rule":
        raise NotImplementedError

    def apply(self, value: Any, ctx: RuleContext) -> Any:
        raise NotImplementedError

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.spec!r})"
