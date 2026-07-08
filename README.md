# py-data-cloak

**py-data-cloak** is a rule-based data anonymization engine for Python. It works
on JSON, NDJSON, CSV, and SQL dumps from the command line, integrates with the
Django ORM for safe `dumpdata` exports, and plugs into Pandas for data-science
workflows.

It keeps **referential integrity** (`user_id=42` always masks to the same value
within a session — or across runs with a persistent vault), streams large files
without loading them into memory, and can **auto-detect PII** from a sample to
generate a starter rules file for you.

## Install

```bash
pip install py-data-cloak

# Optional extras
pip install "py-data-cloak[django]"   # Django dumpdata_masked command + mixin
pip install "py-data-cloak[pandas]"   # mask_dataframe helper
pip install "py-data-cloak[vault]"    # encrypted persistent vaults
pip install "py-data-cloak[all]"      # all of the above
```

## Quick start

```yaml
# privacy_rules.yaml
email:           faker:email
ssn:             mask_all_but_last_4
password:        fixed:***REDACTED***
notes:           clear
credit_card:     format_preserve:luhn
salary:          noise:5000
dob:             shift_date:365
user_id:         hash:sha256:mysalt
'*_email':       faker:email           # glob: any column ending in _email
're:.*_secret$': redact                # regex
'user.profile.phone': format_preserve  # nested JSON path
```

```bash
pycloak process users.json   --rules privacy_rules.yaml --output safe.json
pycloak process huge.jsonl   --rules privacy_rules.yaml --output safe.jsonl
pycloak process export.csv   --rules privacy_rules.yaml --output safe.csv
pycloak process dump.sql     --rules privacy_rules.yaml --output safe.sql
pycloak process input.json   --rules privacy_rules.yaml --dry-run
```

Don't know what to mask? Let pycloak guess:

```bash
pycloak scan users.json --output starter_rules.yaml
```

## Rules reference

| Rule | Effect |
| --- | --- |
| `faker:<provider>[:<arg>...]` | Replace with a Faker value (`faker:email`, `faker:name`, ...). |
| `fixed:<value>` | Replace with a static string. |
| `clear` | Replace with `null`. |
| `redact[:<placeholder>]` | Replace with `[REDACTED]` or a custom string. |
| `mask_all_but_last_<n>` | Keep the last N chars, replace the rest with `*`. |
| `partial:<start>:<end>[:<mask_char>]` | Keep N leading and M trailing chars (`john@x.com` -> `j***@x.com`). |
| `format_preserve[:luhn]` | Keep the shape (digits/letters/separators). With `:luhn`, the digit sequence is Luhn-valid. |
| `hash[:<algo>[:<salt>]]` | Deterministic hex digest. Default `sha256`. |
| `noise:<sigma>` | Gaussian noise added to a numeric value. |
| `shift_date:<days>` | Shift a date by a random number of days within `±days`. |
| `custom:<module.path>:<function>` | Call your own `fn(value, ctx) -> masked`. |

### Field matching

* **Exact** — `"email"`, `"user.profile.phone"` (nested JSON path)
* **Glob** — `"*_email"`, `"user.*"`, `"address.[lc]ine?"`
* **Regex** — prefix the pattern with `re:`, e.g. `"re:^.*_secret$"`

Exact rules are checked first; glob and regex follow in declaration order, so
put specific patterns above broader catch-alls.

## Python API

```python
from pycloak import Anonymizer, Vault, load_rules

rules = load_rules("privacy_rules.yaml")
vault = Vault("masked.vault", passphrase="hunter2")   # optional
anonymizer = Anonymizer(rules, seed=42, locale="en_US", vault=vault)

masked = anonymizer.process_record({"email": "alice@example.com", "salary": 95000})
anonymizer.save()   # persist the vault for the next run
```

### Custom rules

```python
from pycloak import register_rule
from pycloak.rules import Rule

@register_rule
class UppercaseRule(Rule):
    @classmethod
    def matches(cls, spec): return spec == "upper"
    @classmethod
    def parse(cls, spec):   return cls()
    def apply(self, value, ctx): return str(value).upper()
```

Or use `custom:my.module:my_func` directly in YAML:

```python
# my_module.py
def my_func(value, ctx):
    return f"<masked:{ctx.field_name}>"
```

```yaml
some_field: custom:my_module:my_func
```

### Pandas

```python
from pycloak.pandas_helper import mask_dataframe

masked_df = mask_dataframe(df, rules)
```

## Django

Add to `INSTALLED_APPS`:

```python
INSTALLED_APPS = [..., "pycloak.django"]
PY_DATA_CLOAK_MASKING_RULES = "privacy_rules.yaml"   # path or dict
PY_DATA_CLOAK_SAFE_REPR = True                       # optional: safer repr for logs
```

Stream-friendly masked dump:

```bash
python manage.py dumpdata_masked auth.User --output safe_users.json --chunk-size 5000
```

Per-instance access via the mixin:

```python
from pycloak.django.mixins import MaskedModelMixin

class User(MaskedModelMixin, models.Model):
    ...

User.objects.first().masked_data()
```

## Versioning

0.2.0 introduces streaming, consistency, SQL/NDJSON support, PII detection,
vaults, Pandas/Django streaming, and the rule registry. The pre-1.0 API may
still evolve; 1.0.0 will lock the public surface.

## License

MIT.
