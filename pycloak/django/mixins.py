from django.conf import settings
from pycloak.masking import Anonymizer, load_rules

class MaskedModelMixin:
    """
    Mixin to provide a .mask() method on the model instance.
    This doesn't change the DB, just returns a masked dict representation.
    """
    
    @classmethod
    def get_masking_rules(cls):
        # Look for rules in settings, could be dict or path to file
        rules_source = getattr(settings, 'PY_DATA_CLOAK_MASKING_RULES', {})
        if isinstance(rules_source, str):
            # assume path
            return load_rules(rules_source)
        return rules_source

    def masked_data(self):
        """Return a dictionary of the model fields with masking applied."""
        rules = self.get_masking_rules()
        anonymizer = Anonymizer(rules)
        
        data = {}
        for field in self._meta.fields:
            val = getattr(self, field.name)
            data[field.name] = anonymizer.mask_value(field.name, val)
        return data

    def  __repr__(self):
        # Optional: safer repr for logs if configured
        if getattr(settings, 'PY_DATA_CLOAK_SAFE_REPR', False):
             return f"<{self.__class__.__name__}: {self.pk} (masked)>"
        return super().__repr__()
