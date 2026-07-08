from ..exceptions import InvalidRuleError, UnknownRuleError
from .base import Rule, RuleContext
from .handlers import (
    RULES,
    ClearRule,
    CustomRule,
    FakerRule,
    FixedRule,
    FormatPreserveRule,
    HashRule,
    MaskAllButLastRule,
    NoiseRule,
    PartialRule,
    RedactRule,
    ShiftDateRule,
    register_rule,
)


def parse_rule(spec) -> Rule:
    """Parse a rule spec string into a Rule instance.

    Spec can be a string ('faker:email', 'clear', ...) or an already-built Rule.
    """
    if isinstance(spec, Rule):
        return spec
    if not isinstance(spec, str):
        raise InvalidRuleError(f"Rule spec must be a string, got {type(spec).__name__}")
    for rule_cls in RULES:
        if rule_cls.matches(spec):
            return rule_cls.parse(spec)
    raise UnknownRuleError(spec)


__all__ = [
    "Rule",
    "RuleContext",
    "RULES",
    "parse_rule",
    "register_rule",
    "ClearRule",
    "CustomRule",
    "FakerRule",
    "FixedRule",
    "FormatPreserveRule",
    "HashRule",
    "MaskAllButLastRule",
    "NoiseRule",
    "PartialRule",
    "RedactRule",
    "ShiftDateRule",
]
