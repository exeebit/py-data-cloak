"""Optional persistent vault for the consistency cache.

A vault stores the (rule_spec, original) -> masked mapping on disk so the
same input always maps to the same output across runs. This is what
makes things like 'shift_date' or 'faker:email' deterministic between
two separate dump-and-mask invocations.

If a passphrase is supplied, the vault file is encrypted with Fernet
(symmetric AES-128 + HMAC-SHA256). Fernet lives in the optional
'cryptography' extra::

    pip install "py-data-cloak[vault]"

Without a passphrase, the vault is a plain JSON file -- still useful for
deterministic re-runs, but NOT safe to commit.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from .exceptions import VaultError


_MAGIC = b"PYCV1\n"  # plain JSON marker — first line of a plaintext vault
_ENC_MAGIC = b"PYCE1\n"  # encrypted vault marker
_KDF_ITERATIONS = 200_000


class Vault:
    """File-backed cache of (rule_spec, original_value) -> masked_value."""

    def __init__(self, path: str, passphrase: Optional[str] = None):
        self.path = Path(path)
        self.passphrase = passphrase
        if passphrase is not None:
            self._fernet = _build_fernet(passphrase)
        else:
            self._fernet = None

    # ------------------------------------------------------------------ public

    def load(self) -> Dict[Tuple[str, Any], Any]:
        if not self.path.exists():
            return {}
        data = self.path.read_bytes()
        if data.startswith(_ENC_MAGIC):
            if self._fernet is None:
                raise VaultError(f"Vault at {self.path} is encrypted; provide a passphrase")
            try:
                payload = self._fernet.decrypt(data[len(_ENC_MAGIC) :])
            except Exception as e:
                raise VaultError(f"Failed to decrypt vault at {self.path}") from e
            body = payload.decode("utf-8")
        elif data.startswith(_MAGIC):
            body = data[len(_MAGIC) :].decode("utf-8")
        else:
            raise VaultError(f"Vault at {self.path} has an unrecognized format")
        return _deserialize(body)

    def save(self, cache: Dict[Tuple[str, Any], Any]) -> None:
        body = _serialize(cache).encode("utf-8")
        if self._fernet is not None:
            payload = _ENC_MAGIC + self._fernet.encrypt(body)
        else:
            payload = _MAGIC + body
        # Write atomically: tmp file + rename
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_bytes(payload)
        os.replace(tmp, self.path)


# --- serialization ------------------------------------------------------------

def _serialize(cache: Dict[Tuple[str, Any], Any]) -> str:
    entries = []
    for (spec, original), masked in cache.items():
        entries.append({"rule": spec, "in": original, "out": masked})
    return json.dumps({"version": 1, "entries": entries}, default=str)


def _deserialize(body: str) -> Dict[Tuple[str, Any], Any]:
    payload = json.loads(body)
    out: Dict[Tuple[str, Any], Any] = {}
    for entry in payload.get("entries", []):
        out[(entry["rule"], entry["in"])] = entry["out"]
    return out


# --- encryption (lazy) --------------------------------------------------------

def _build_fernet(passphrase: str):
    try:
        from cryptography.fernet import Fernet
    except ImportError as e:
        raise VaultError(
            "Encrypted vaults require the 'cryptography' package. "
            "Install it with: pip install \"py-data-cloak[vault]\""
        ) from e
    # Derive a Fernet-compatible key from the passphrase with PBKDF2.
    # Salt is a constant per-file marker — passphrase is the secret.
    salt = b"pycloak-vault-v1"
    key = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, _KDF_ITERATIONS, dklen=32)
    return Fernet(base64.urlsafe_b64encode(key))
