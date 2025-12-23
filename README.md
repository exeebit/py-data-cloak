# py-data-cloak

**py-data-cloak** is a robust, rule-based data anonymization and sanitization engine that works seamlessly on static files (CSV/JSON/SQL dumps) via CLI and integrates natively into the Django ORM for "safe dumps."

## Features

*   **Declarative Ruleset**: Define how to mask data using YAML or Python dictionaries.
*   **Consistency**: Maintains referential integrity (e.g., "User 1" is always masked to the same value within a session).
*   **Streaming Support**: Efficiently handles large datasets.
*   **Django Integration**: Drop-in `dumpdata_masked` command and `MaskedModelMixin`.
*   **CLI Tool**: Process JSON/CSV files or pipe SQL dumps.

## Installation

```bash
pip install py-data-cloak
# For Django support
pip install "py-data-cloak[django]"
```

## Usage

### CLI

1.  Define your rules in `privacy_rules.yaml`:
    ```yaml
    email: "faker:email"
    ssn: "mask_all_but_last_4"
    password: "fixed:secret"
    ```

2.  Run the tool:
    ```bash
    pycloak process input.json --rules=privacy_rules.yaml --output=clean.json
    ```

### Django

1.  Add `pycloak.django` to your `INSTALLED_APPS`.
2.  Use the management command:
    ```bash
    python manage.py dumpdata_masked auth.User --output=safe_users.json
    ```

## Rules Reference

*   `faker:<provider>`: Use any Faker provider (e.g., `faker:name`, `faker:email`).
*   `fixed:<value>`: Replace with a static value.
*   `mask_all_but_last_<n>`: Mask characters with `*` except the last `n`.
*   `clear`: Set to `null` or empty string.
