"""
Tests for epoch-based keyring management.

Tests keyring creation, migration, rotation, lookup, and edge cases.
"""

import json
import tempfile
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from qp_capsule.exceptions import KeyringError
from qp_capsule.keyring import Epoch, Keyring, _make_fingerprint


@pytest.fixture
def temp_dir():
    """Provide a temporary directory for keys and keyring."""
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture
def key_path(temp_dir):
    return temp_dir / "key"


@pytest.fixture
def keyring_path(temp_dir):
    return temp_dir / "keyring.json"


@pytest.fixture
def keyring(keyring_path, key_path):
    return Keyring(keyring_path=keyring_path, key_path=key_path)


@pytest.fixture
def existing_key(key_path):
    """Create a key file with a generated Ed25519 key."""
    sk = SigningKey.generate()
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(bytes(sk))
    return sk


class TestEpoch:
    """Test Epoch dataclass serialization."""

    def test_to_dict_roundtrip(self):
        epoch = Epoch(
            epoch=0,
            algorithm="ed25519",
            public_key_hex="abcd1234" * 8,
            fingerprint="qp_key_abcd",
            created_at="2026-01-01T00:00:00+00:00",
            rotated_at=None,
            status="active",
        )
        d = epoch.to_dict()
        restored = Epoch.from_dict(d)
        assert restored.epoch == 0
        assert restored.algorithm == "ed25519"
        assert restored.fingerprint == "qp_key_abcd"
        assert restored.status == "active"
        assert restored.rotated_at is None

    def test_from_dict_with_rotated_at(self):
        d = {
            "epoch": 1,
            "algorithm": "ed25519",
            "public_key_hex": "ff" * 32,
            "fingerprint": "qp_key_ffff",
            "created_at": "2026-01-01T00:00:00+00:00",
            "rotated_at": "2026-02-01T00:00:00+00:00",
            "status": "retired",
        }
        epoch = Epoch.from_dict(d)
        assert epoch.status == "retired"
        assert epoch.rotated_at == "2026-02-01T00:00:00+00:00"


class TestMakeFingerprint:
    def test_creates_qp_key_prefix(self):
        assert _make_fingerprint("abcd1234") == "qp_key_abcd"

    def test_uses_first_four_hex_chars(self):
        assert _make_fingerprint("ff00aabb" + "00" * 28) == "qp_key_ff00"


class TestKeyringCreation:
    """Test creating keyrings from scratch."""

    def test_empty_keyring_when_nothing_exists(self, keyring):
        assert keyring.epochs == []
        assert keyring.active_epoch == 0
        assert keyring.get_active() is None

    def test_keyring_path_property(self, keyring, keyring_path):
        assert keyring.path == keyring_path

    def test_key_path_property(self, keyring, key_path):
        assert keyring.key_path == key_path

    def test_to_dict_empty(self, keyring):
        d = keyring.to_dict()
        assert d["version"] == 1
        assert d["active_epoch"] == 0
        assert d["epochs"] == []


class TestKeyringMigration:
    """Test seamless migration from existing key files."""

    def test_migrates_existing_key(self, keyring, existing_key):
        epochs = keyring.epochs
        assert len(epochs) == 1
        assert epochs[0].epoch == 0
        assert epochs[0].status == "active"
        assert epochs[0].algorithm == "ed25519"

        expected_pub = existing_key.verify_key.encode().hex()
        assert epochs[0].public_key_hex == expected_pub

    def test_migration_creates_keyring_file(self, keyring, keyring_path, existing_key):
        _ = keyring.epochs
        assert keyring_path.exists()

        data = json.loads(keyring_path.read_text("utf-8"))
        assert data["version"] == 1
        assert len(data["epochs"]) == 1

    def test_migration_fingerprint_format(self, keyring, existing_key):
        epoch = keyring.epochs[0]
        assert epoch.fingerprint.startswith("qp_key_")
        assert epoch.fingerprint == f"qp_key_{epoch.public_key_hex[:4]}"

    def test_migration_not_triggered_if_keyring_exists(self, keyring_path, key_path, existing_key):
        keyring_path.write_text('{"version": 1, "active_epoch": 0, "epochs": []}')
        kr = Keyring(keyring_path=keyring_path, key_path=key_path)
        assert kr.epochs == []


class TestKeyringLoad:
    """Test loading keyrings from disk."""

    def test_load_valid_keyring(self, keyring_path, key_path):
        data = {
            "version": 1,
            "active_epoch": 0,
            "epochs": [
                {
                    "epoch": 0,
                    "algorithm": "ed25519",
                    "public_key_hex": "aa" * 32,
                    "fingerprint": "qp_key_aaaa",
                    "created_at": "2026-01-01T00:00:00+00:00",
                    "rotated_at": None,
                    "status": "active",
                }
            ],
        }
        keyring_path.write_text(json.dumps(data))

        kr = Keyring(keyring_path=keyring_path, key_path=key_path)
        assert len(kr.epochs) == 1
        assert kr.active_epoch == 0

    def test_load_wrong_version_raises(self, keyring_path, key_path):
        data = {"version": 99, "active_epoch": 0, "epochs": []}
        keyring_path.write_text(json.dumps(data))

        kr = Keyring(keyring_path=keyring_path, key_path=key_path)
        with pytest.raises(KeyringError, match="Unsupported keyring version"):
            _ = kr.epochs

    def test_load_corrupt_json_raises(self, keyring_path, key_path):
        keyring_path.write_text("{{not valid json")

        kr = Keyring(keyring_path=keyring_path, key_path=key_path)
        with pytest.raises(KeyringError, match="Failed to read keyring"):
            _ = kr.epochs

    def test_load_is_idempotent(self, keyring, existing_key):
        _ = keyring.epochs
        epochs_again = keyring.epochs
        assert len(epochs_again) == 1

    def test_explicit_load_resets(self, keyring_path, key_path, existing_key):
        kr = Keyring(keyring_path=keyring_path, key_path=key_path)
        kr.load()
        assert len(kr.epochs) == 1
        kr.load()
        assert len(kr.epochs) == 1


class TestKeyringRotation:
    """Test key rotation with epoch tracking."""

    def test_rotate_from_empty(self, keyring):
        epoch = keyring.rotate()
        assert epoch.epoch == 0
        assert epoch.status == "active"
        assert epoch.fingerprint.startswith("qp_key_")
        assert len(keyring.epochs) == 1

    def test_rotate_retires_old(self, keyring, existing_key):
        old = keyring.epochs[0]
        assert old.status == "active"

        new = keyring.rotate()
        epochs = keyring.epochs

        assert len(epochs) == 2
        assert epochs[0].status == "retired"
        assert epochs[0].rotated_at is not None
        assert epochs[1].status == "active"
        assert new.epoch == 1

    def test_double_rotate(self, keyring, existing_key):
        keyring.rotate()
        keyring.rotate()
        epochs = keyring.epochs

        assert len(epochs) == 3
        assert epochs[0].status == "retired"
        assert epochs[1].status == "retired"
        assert epochs[2].status == "active"
        assert keyring.active_epoch == 2

    def test_rotate_writes_new_key_file(self, keyring, key_path, existing_key):
        old_bytes = key_path.read_bytes()
        keyring.rotate()
        new_bytes = key_path.read_bytes()
        assert old_bytes != new_bytes

    def test_rotate_saves_keyring(self, keyring, keyring_path, existing_key):
        keyring.rotate()
        data = json.loads(keyring_path.read_text("utf-8"))
        assert len(data["epochs"]) == 2
        assert data["active_epoch"] == 1

    def test_rotate_key_permissions(self, keyring, key_path, existing_key):
        keyring.rotate()
        stat = key_path.stat()
        assert stat.st_mode & 0o777 == 0o600


class TestKeyringLookup:
    """Test epoch lookup by fingerprint."""

    def test_lookup_by_new_format(self, keyring, existing_key):
        epoch = keyring.epochs[0]
        found = keyring.lookup(epoch.fingerprint)
        assert found is not None
        assert found.epoch == 0

    def test_lookup_by_legacy_16char(self, keyring, existing_key):
        epoch = keyring.epochs[0]
        legacy_fp = epoch.public_key_hex[:16]
        found = keyring.lookup(legacy_fp)
        assert found is not None
        assert found.epoch == 0

    def test_lookup_nonexistent_returns_none(self, keyring, existing_key):
        assert keyring.lookup("qp_key_zzzz") is None

    def test_lookup_public_key(self, keyring, existing_key):
        epoch = keyring.epochs[0]
        pub = keyring.lookup_public_key(epoch.fingerprint)
        assert pub == epoch.public_key_hex

    def test_lookup_public_key_missing(self, keyring, existing_key):
        assert keyring.lookup_public_key("nonexistent") is None

    def test_lookup_after_rotation(self, keyring, existing_key):
        old_fp = keyring.epochs[0].fingerprint
        new_epoch = keyring.rotate()

        assert keyring.lookup(old_fp) is not None
        assert keyring.lookup(new_epoch.fingerprint) is not None


class TestKeyringRegister:
    """Test idempotent key registration."""

    def test_register_new_key(self, keyring):
        sk = SigningKey.generate()
        epoch = keyring.register_key(sk)

        assert epoch.epoch == 0
        assert epoch.status == "active"
        assert epoch.public_key_hex == sk.verify_key.encode().hex()

    def test_register_same_key_is_idempotent(self, keyring):
        sk = SigningKey.generate()
        e1 = keyring.register_key(sk)
        e2 = keyring.register_key(sk)
        assert e1.epoch == e2.epoch
        assert len(keyring.epochs) == 1

    def test_register_appends_to_existing(self, keyring, existing_key):
        new_sk = SigningKey.generate()
        epoch = keyring.register_key(new_sk)
        assert epoch.epoch == 1
        assert len(keyring.epochs) == 2


class TestKeyringExport:
    """Test public key export."""

    def test_export_active_key(self, keyring, existing_key):
        pub = keyring.export_public_key()
        assert pub is not None
        assert pub == existing_key.verify_key.encode().hex()

    def test_export_returns_none_when_empty(self, keyring):
        assert keyring.export_public_key() is None

    def test_export_after_rotation(self, keyring, existing_key):
        old_pub = keyring.export_public_key()
        keyring.rotate()
        new_pub = keyring.export_public_key()
        assert new_pub is not None
        assert new_pub != old_pub


class TestKeyringAtomicWrite:
    """Test that saves are crash-safe."""

    def test_save_creates_parent_dirs(self, temp_dir):
        deep_path = temp_dir / "a" / "b" / "keyring.json"
        kr = Keyring(keyring_path=deep_path, key_path=temp_dir / "key")
        kr.rotate()
        assert deep_path.exists()

    def test_keyring_file_is_valid_json(self, keyring, keyring_path, existing_key):
        _ = keyring.epochs
        data = json.loads(keyring_path.read_text("utf-8"))
        assert "version" in data
        assert "epochs" in data


class TestKeyringAllRetired:
    """Test keyring when all epochs are retired."""

    def test_get_active_returns_none_when_all_retired(self, keyring, existing_key):
        _ = keyring.epochs
        keyring.rotate()
        for ep in keyring._epochs:
            ep.status = "retired"
        assert keyring.get_active() is None

    def test_export_returns_none_when_all_retired(self, keyring, existing_key):
        _ = keyring.epochs
        for ep in keyring._epochs:
            ep.status = "retired"
        assert keyring.export_public_key() is None


class TestKeyringMigrationEdgeCases:
    """Test migration error handling."""

    def test_corrupt_key_file_raises(self, temp_dir):
        key_path = temp_dir / "key"
        key_path.write_bytes(b"not a valid ed25519 key")
        kr = Keyring(keyring_path=temp_dir / "keyring.json", key_path=key_path)
        with pytest.raises(KeyringError, match="Failed to migrate"):
            _ = kr.epochs
