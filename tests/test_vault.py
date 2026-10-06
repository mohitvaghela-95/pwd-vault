from cryptography.fernet import Fernet
import pytest

from vault import Vault


@pytest.fixture
def vault_with_key(tmp_path):
    """Return a vault whose key is stored only in pytest's temporary directory."""
    vault = Vault()
    key_path = tmp_path / "master.key"
    vault.create_key(key_path)
    return vault, key_path


def test_create_key_writes_a_usable_key(tmp_path):
    vault = Vault()
    key_path = tmp_path / "master.key"

    vault.create_key(key_path)

    assert key_path.read_bytes() == vault.key
    assert len(vault.key) == 44


def test_create_key_refuses_to_overwrite_existing_key(tmp_path):
    key_path = tmp_path / "master.key"
    key_path.write_bytes(b"existing-key")

    with pytest.raises(FileExistsError, match="exists"):
        Vault().create_key(key_path)

    assert key_path.read_bytes() == b"existing-key"


def test_create_key_can_overwrite_when_requested(tmp_path):
    key_path = tmp_path / "master.key"
    key_path.write_bytes(b"old-key")

    vault = Vault()
    vault.create_key(key_path, overwrite=True)

    assert key_path.read_bytes() == vault.key
    assert key_path.read_bytes() != b"old-key"


def test_load_key_reads_key_from_disk(vault_with_key):
    created_vault, key_path = vault_with_key
    loaded_vault = Vault()

    loaded_vault.load_key(key_path)

    assert loaded_vault.key == created_vault.key


def test_load_key_requires_an_existing_file(tmp_path):
    with pytest.raises(FileNotFoundError, match="not found"):
        Vault().load_key(tmp_path / "missing.key")


def test_passwords_are_encrypted_on_disk_and_can_be_loaded(vault_with_key, tmp_path):
    vault, _ = vault_with_key
    passwords_path = tmp_path / "passwords"
    passwords = {"email": "password123", "github": "testingtesting"}

    vault.create_database(passwords_path, passwords)

    contents = passwords_path.read_text()
    assert "password123" not in contents
    assert "testingtesting" not in contents

    loaded_vault = Vault()
    loaded_vault.key = vault.key
    loaded_vault.load_passwords(passwords_path)

    assert loaded_vault.get_password("email") == "password123"
    assert loaded_vault.get_password("github") == "testingtesting"


def test_add_password_appends_an_encrypted_entry(vault_with_key, tmp_path):
    vault, _ = vault_with_key
    passwords_path = tmp_path / "passwords"
    vault.create_database(passwords_path)

    vault.add_password("example", "secret")

    site, encrypted = passwords_path.read_text().strip().split(":")
    assert site == "example"
    assert Fernet(vault.key).decrypt(encrypted.encode()).decode() == "secret"


def test_get_password_raises_for_an_unknown_site():
    with pytest.raises(KeyError):
        Vault().get_password("unknown")
