from __future__ import annotations

from django.conf import settings

from pycloak.anonymizer import Anonymizer
from pycloak.config import load_rules


class MaskedModelMixin:
    """Add a ``.masked_data()`` method to a Django model.

    Reads its rules from ``settings.PY_DATA_CLOAK_MASKING_RULES`` (which may
    be either a dict or a path to a YAML file).
    """

    @classmethod
    def get_masking_rules(cls) -> dict:
        source = getattr(settings, "PY_DATA_CLOAK_MASKING_RULES", {})
        if isinstance(source, str):
            return load_rules(source)
        return source or {}

    def masked_data(self) -> dict:
        """Return a dict of this instance's fields with masking applied."""
        rules = self.get_masking_rules()
        anonymizer = Anonymizer(rules)
        return {
            field.name: anonymizer.mask_value(field.name, getattr(self, field.name))
            for field in self._meta.fields
        }

    def __repr__(self) -> str:
        if getattr(settings, "PY_DATA_CLOAK_SAFE_REPR", False):
            return f"<{self.__class__.__name__}: {self.pk} (masked)>"
        return super().__repr__()
