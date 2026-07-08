import pytest

from pycloak import Anonymizer, Vault
from pycloak.exceptions import VaultError


def test_vault_persists_across_anonymizers(tmp_path):
    vault_path = tmp_path / "v.vault"
    rules = {"email": "faker:email"}

    a1 = Anonymizer(rules, seed=1, vault=Vault(str(vault_path)))
    masked = a1.mask_value("email", "alice@example.com")
    a1.save()

    a2 = Anonymizer(rules, seed=999, vault=Vault(str(vault_path)))
    # Different seed; would diverge without the vault.
    assert a2.mask_value("email", "alice@example.com") == masked


def test_encrypted_vault_roundtrip(tmp_path):
    pytest.importorskip("cryptography")
    vault_path = tmp_path / "enc.vault"

    a1 = Anonymizer({"email": "faker:email"}, seed=1,
                    vault=Vault(str(vault_path), passphrase="hunter2"))
    masked = a1.mask_value("email", "alice@example.com")
    a1.save()

    # Verify file is not plaintext JSON
    raw = vault_path.read_bytes()
    assert raw.startswith(b"PYCE1\n")
    assert b"alice@example.com" not in raw

    a2 = Anonymizer({"email": "faker:email"}, seed=2,
                    vault=Vault(str(vault_path), passphrase="hunter2"))
    assert a2.mask_value("email", "alice@example.com") == masked


def test_encrypted_vault_wrong_passphrase(tmp_path):
    pytest.importorskip("cryptography")
    vault_path = tmp_path / "enc.vault"

    a = Anonymizer({"x": "fixed:X"}, vault=Vault(str(vault_path), passphrase="pw1"))
    a.mask_value("x", "y")
    a.save()

    with pytest.raises(VaultError):
        Vault(str(vault_path), passphrase="WRONG").load()


def test_vault_missing_file_returns_empty(tmp_path):
    vault_path = tmp_path / "nope.vault"
    assert Vault(str(vault_path)).load() == {}
