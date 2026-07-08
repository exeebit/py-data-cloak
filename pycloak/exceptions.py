class PycloakError(Exception):
    """Base exception for all pycloak errors."""


class RuleError(PycloakError):
    """Raised when a rule cannot be parsed or applied."""


class UnknownRuleError(RuleError):
    def __init__(self, spec):
        super().__init__(f"Unknown rule: {spec!r}")
        self.spec = spec


class InvalidRuleError(RuleError):
    pass


class VaultError(PycloakError):
    pass


class FormatError(PycloakError):
    pass
