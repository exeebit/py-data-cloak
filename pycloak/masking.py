"""Backward-compat shim for code that imports from `pycloak.masking`.

The implementation lives in `pycloak.anonymizer` (engine), `pycloak.rules`
(rule registry), and `pycloak.config` (loaders) as of 0.2.0. This module
will be removed in 1.0.
"""
from warnings import warn

from .anonymizer import Anonymizer
from .config import load_rules

warn(
    "pycloak.masking is deprecated; import from pycloak directly "
    "(e.g. `from pycloak import Anonymizer, load_rules`).",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = ["Anonymizer", "load_rules"]
