"""py-data-cloak: rule-based data anonymization for files, SQL dumps, and Django."""
from .anonymizer import Anonymizer
from .config import load_rules, validate_rules
from .detect import detect_rules
from .exceptions import (
    FormatError,
    InvalidRuleError,
    PycloakError,
    RuleError,
    UnknownRuleError,
    VaultError,
)
from .matching import FieldMatcher
from .rules import Rule, RuleContext, parse_rule, register_rule
from .vault import Vault

__version__ = "0.2.0"

__all__ = [
    "Anonymizer",
    "FieldMatcher",
    "Rule",
    "RuleContext",
    "Vault",
    "detect_rules",
    "load_rules",
    "parse_rule",
    "register_rule",
    "validate_rules",
    "PycloakError",
    "RuleError",
    "UnknownRuleError",
    "InvalidRuleError",
    "FormatError",
    "VaultError",
    "__version__",
]
