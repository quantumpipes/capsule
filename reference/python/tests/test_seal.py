"""
Tests for Seal (cryptographic sealing).

Tests SHA3-256 hashing and Ed25519 signing.
These tests cover the Tier 1 (Ed25519-only) behavior.
"""

import tempfile
from pathlib import Path

import pytest

from qp_capsule.capsule import Capsule, ReasoningSection, TriggerSection
from qp_capsule.seal import Seal, compute_hash


@pytest.fixture
def temp_key_path():
    """Provide a temporary key path for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir) / "test_key"


@pytest.fixture
def seal(temp_key_path):
    """Provide a Seal instance with temporary key."""
    return Seal(key_path=temp_key_path)


@pytest.fixture
def sample_capsule():
    """Provide a sample Capsule for testing."""
    return Capsule(
        trigger=TriggerSection(
            type="user_request",
            source="test_user",
            request="Test task",
        ),
        reasoning=ReasoningSection(
            options_considered=["option_a", "option_b"],
            selected_option="option_a",
            reasoning="Option A is the best choice",
            confidence=0.9,
        ),
    )


class TestSealCreation:
    """Test Seal initialization."""

    def test_creates_key_on_first_use(self, seal, temp_key_path, sample_capsule):
        """Key is created on first seal operation."""
        assert not temp_key_path.exists()

        seal.seal(sample_capsule)

        assert temp_key_path.exists()

    def test_key_has_restricted_permissions(self, seal, temp_key_path, sample_capsule):
        """Key file has owner-only permissions."""
        seal.seal(sample_capsule)

        # Check permissions (0o600 = owner read/write only)
        mode = temp_key_path.stat().st_mode & 0o777
        assert mode == 0o600

    def test_reuses_existing_key(self, temp_key_path, sample_capsule):
        """Same key is used across instances."""
        seal1 = Seal(key_path=temp_key_path)
        seal2 = Seal(key_path=temp_key_path)

        seal1.seal(sample_capsule)
        fingerprint1 = seal1.get_key_fingerprint()

        capsule2 = Capsule()
        seal2.seal(capsule2)
        fingerprint2 = seal2.get_key_fingerprint()

        assert fingerprint1 == fingerprint2


class TestSealing:
    """Test Capsule sealing."""

    def test_seal_sets_hash(self, seal, sample_capsule):
        """Sealing sets the hash field."""
        assert sample_capsule.hash == ""

        seal.seal(sample_capsule)

        assert sample_capsule.hash != ""
        assert len(sample_capsule.hash) == 64  # SHA3-256 hex = 64 chars

    def test_seal_sets_signature(self, seal, sample_capsule):
        """Sealing sets the signature field."""
        assert sample_capsule.signature == ""

        seal.seal(sample_capsule)

        assert sample_capsule.signature != ""

    def test_seal_sets_metadata(self, seal, sample_capsule):
        """Sealing sets signed_at and signed_by."""
        assert sample_capsule.signed_at is None
        assert sample_capsule.signed_by == ""

        seal.seal(sample_capsule)

        assert sample_capsule.signed_at is not None
        assert sample_capsule.signed_by != ""

    def test_sealed_capsule_is_sealed(self, seal, sample_capsule):
        """is_sealed() returns True after sealing."""
        assert not sample_capsule.is_sealed()

        seal.seal(sample_capsule)

        assert sample_capsule.is_sealed()

    def test_same_content_same_hash(self, seal):
        """Same content produces same hash."""
        from datetime import UTC, datetime

        fixed_time = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)

        capsule1 = Capsule(
            trigger=TriggerSection(type="test", source="test", request="test", timestamp=fixed_time)
        )
        capsule2 = Capsule(
            trigger=TriggerSection(type="test", source="test", request="test", timestamp=fixed_time)
        )

        # Force same ID for comparison
        capsule2.id = capsule1.id

        hash1 = compute_hash(capsule1.to_dict())
        hash2 = compute_hash(capsule2.to_dict())

        assert hash1 == hash2

    def test_different_content_different_hash(self, seal):
        """Different content produces different hash."""
        capsule1 = Capsule(trigger=TriggerSection(type="test", source="test", request="request_1"))
        capsule2 = Capsule(trigger=TriggerSection(type="test", source="test", request="request_2"))

        hash1 = compute_hash(capsule1.to_dict())
        hash2 = compute_hash(capsule2.to_dict())

        assert hash1 != hash2


class TestVerification:
    """Test Capsule verification."""

    def test_verify_valid_capsule(self, seal, sample_capsule):
        """Valid sealed Capsule verifies successfully."""
        seal.seal(sample_capsule)

        assert seal.verify(sample_capsule) is True

    def test_verify_unsealed_capsule_fails(self, seal, sample_capsule):
        """Unsealed Capsule fails verification."""
        assert seal.verify(sample_capsule) is False

    def test_verify_tampered_content_fails(self, seal, sample_capsule):
        """Tampered content fails verification."""
        seal.seal(sample_capsule)

        # Tamper with content
        sample_capsule.reasoning.reasoning = "TAMPERED"

        assert seal.verify(sample_capsule) is False

    def test_verify_tampered_hash_fails(self, seal, sample_capsule):
        """Tampered hash fails verification."""
        seal.seal(sample_capsule)

        # Tamper with hash
        sample_capsule.hash = "a" * 64

        assert seal.verify(sample_capsule) is False

    def test_verify_tampered_signature_fails(self, seal, sample_capsule):
        """Tampered signature fails verification."""
        seal.seal(sample_capsule)

        # Tamper with signature
        sample_capsule.signature = "b" * len(sample_capsule.signature)

        assert seal.verify(sample_capsule) is False


class TestPublicKey:
    """Test public key operations."""

    def test_get_public_key(self, seal, sample_capsule):
        """Can get public key as hex string."""
        seal.seal(sample_capsule)  # Ensure key exists

        public_key = seal.get_public_key()

        assert isinstance(public_key, str)
        assert len(public_key) == 64  # Ed25519 public key = 32 bytes = 64 hex chars

    def test_get_key_fingerprint(self, seal, sample_capsule):
        """Fingerprint is first 16 chars of public key."""
        seal.seal(sample_capsule)

        fingerprint = seal.get_key_fingerprint()
        public_key = seal.get_public_key()

        assert fingerprint == public_key[:16]

    def test_verify_with_key(self, seal, sample_capsule):
        """Can verify with explicit public key."""
        seal.seal(sample_capsule)
        public_key = seal.get_public_key()

        # Create new Seal instance (no access to private key)
        with tempfile.TemporaryDirectory() as tmpdir:
            other_seal = Seal(key_path=Path(tmpdir) / "other_key")

            # Should be able to verify with public key
            assert other_seal.verify_with_key(sample_capsule, public_key) is True


class TestSealKeyringIntegration:
    """Test Seal behavior when configured with a Keyring."""

    def test_seal_uses_keyring_fingerprint_format(self, temp_key_path):
        """Capsules sealed with a keyring get the qp_key_XXXX format."""
        from qp_capsule.keyring import Keyring

        kr = Keyring(
            keyring_path=temp_key_path.parent / "keyring.json",
            key_path=temp_key_path,
        )
        s = Seal(key_path=temp_key_path, keyring=kr)
        capsule = Capsule(trigger=TriggerSection(type="test", source="t", request="r"))
        s.seal(capsule)

        assert capsule.signed_by.startswith("qp_key_")

    def test_fingerprint_falls_back_when_keyring_has_no_active(self, temp_key_path):
        """get_key_fingerprint falls back to 16-char hex when keyring has no active epoch."""
        from qp_capsule.keyring import Keyring

        kr = Keyring(
            keyring_path=temp_key_path.parent / "keyring.json",
            key_path=temp_key_path,
        )
        s = Seal(key_path=temp_key_path, keyring=kr)
        s.seal(Capsule())

        kr._epochs[0].status = "retired"

        fp = s.get_key_fingerprint()
        assert not fp.startswith("qp_key_")
        assert len(fp) == 16

    def test_verify_falls_back_when_keyring_lookup_misses(self, temp_key_path):
        """verify() falls back to local key when signed_by isn't in the keyring."""
        from qp_capsule.keyring import Keyring

        kr = Keyring(
            keyring_path=temp_key_path.parent / "keyring.json",
            key_path=temp_key_path,
        )
        s = Seal(key_path=temp_key_path, keyring=kr)

        capsule = Capsule(trigger=TriggerSection(type="test", source="t", request="r"))
        s.seal(capsule)
        capsule.signed_by = "unknown_fingerprint"

        assert s.verify(capsule) is True

    def test_verify_uses_keyring_for_old_epoch(self, temp_key_path):
        """verify() resolves old-epoch key from keyring for capsules signed before rotation."""
        from qp_capsule.keyring import Keyring

        kr = Keyring(
            keyring_path=temp_key_path.parent / "keyring.json",
            key_path=temp_key_path,
        )
        s = Seal(key_path=temp_key_path, keyring=kr)

        capsule = Capsule(trigger=TriggerSection(type="test", source="t", request="r"))
        s.seal(capsule)
        old_fp = capsule.signed_by

        kr.rotate()
        s2 = Seal(key_path=temp_key_path, keyring=kr)

        assert s2.verify(capsule) is True
        assert capsule.signed_by == old_fp

    def test_verify_with_empty_signed_by_falls_back(self, temp_key_path):
        """verify() falls back to local key when capsule has empty signed_by."""
        from qp_capsule.keyring import Keyring

        kr = Keyring(
            keyring_path=temp_key_path.parent / "keyring.json",
            key_path=temp_key_path,
        )
        s = Seal(key_path=temp_key_path, keyring=kr)

        capsule = Capsule(trigger=TriggerSection(type="test", source="t", request="r"))
        s.seal(capsule)
        capsule.signed_by = ""

        assert s.verify(capsule) is True

    def test_ensure_keys_registers_with_keyring(self, temp_key_path):
        """_ensure_keys() auto-registers the generated key in the keyring."""
        from qp_capsule.keyring import Keyring

        kr = Keyring(
            keyring_path=temp_key_path.parent / "keyring.json",
            key_path=temp_key_path,
        )
        assert kr.epochs == []

        s = Seal(key_path=temp_key_path, keyring=kr)
        s.seal(Capsule())

        assert len(kr.epochs) == 1
        assert kr.epochs[0].status == "active"

    def test_ensure_keys_with_existing_key_registers_once(self, temp_key_path):
        """Loading an existing key also registers it, idempotently."""
        from nacl.signing import SigningKey as SK

        from qp_capsule.keyring import Keyring

        sk = SK.generate()
        temp_key_path.parent.mkdir(parents=True, exist_ok=True)
        temp_key_path.write_bytes(bytes(sk))

        kr = Keyring(
            keyring_path=temp_key_path.parent / "keyring.json",
            key_path=temp_key_path,
        )
        s = Seal(key_path=temp_key_path, keyring=kr)
        s.seal(Capsule())
        s2 = Seal(key_path=temp_key_path, keyring=kr)
        s2.seal(Capsule())

        assert len(kr.epochs) == 1


class TestSealedDictIntegration:
    """Test to_sealed_dict / from_sealed_dict with real cryptographic sealing."""

    def test_to_sealed_dict_after_real_seal(self, seal, sample_capsule):
        """to_sealed_dict returns real crypto fields after Seal.seal()."""
        seal.seal(sample_capsule)

        d = sample_capsule.to_sealed_dict()

        assert d["hash"] == sample_capsule.hash
        assert len(d["hash"]) == 64
        assert d["signature"] == sample_capsule.signature
        assert len(d["signature"]) > 0
        assert d["signed_by"] == sample_capsule.signed_by
        assert d["signed_at"] is not None

    def test_sealed_dict_hash_matches_content_hash(self, seal, sample_capsule):
        """The hash in to_sealed_dict equals compute_hash of canonical content."""
        seal.seal(sample_capsule)

        sealed = sample_capsule.to_sealed_dict()
        expected = compute_hash(sample_capsule.to_dict())

        assert sealed["hash"] == expected

    def test_sealed_dict_roundtrip_verifies(self, seal, sample_capsule):
        """seal -> to_sealed_dict -> from_sealed_dict -> verify passes."""
        seal.seal(sample_capsule)
        d = sample_capsule.to_sealed_dict()

        restored = Capsule.from_sealed_dict(d)

        assert restored.is_sealed()
        assert seal.verify(restored) is True

    def test_sealed_dict_roundtrip_preserves_all_seal_fields(self, seal, sample_capsule):
        """Every seal field survives the roundtrip through to_sealed_dict/from_sealed_dict."""
        seal.seal(sample_capsule)
        d = sample_capsule.to_sealed_dict()
        restored = Capsule.from_sealed_dict(d)

        assert restored.hash == sample_capsule.hash
        assert restored.signature == sample_capsule.signature
        assert restored.signature_pq == sample_capsule.signature_pq
        assert restored.signed_by == sample_capsule.signed_by
        assert restored.signed_at == sample_capsule.signed_at

    def test_sealed_dict_pq_field_empty_when_disabled(self, seal, sample_capsule):
        """signature_pq is empty string when post-quantum is not enabled."""
        seal.seal(sample_capsule)
        d = sample_capsule.to_sealed_dict()

        assert d["signature_pq"] == ""


class TestComputeHash:
    """Test standalone hash function."""

    def test_compute_hash_returns_hex(self):
        """compute_hash returns hex string."""
        result = compute_hash({"key": "value"})

        assert isinstance(result, str)
        assert len(result) == 64

    def test_compute_hash_is_deterministic(self):
        """Same input produces same hash."""
        data = {"a": 1, "b": 2}

        hash1 = compute_hash(data)
        hash2 = compute_hash(data)

        assert hash1 == hash2

    def test_compute_hash_key_order_independent(self):
        """Hash is same regardless of key order in input."""
        data1 = {"a": 1, "b": 2}
        data2 = {"b": 2, "a": 1}

        assert compute_hash(data1) == compute_hash(data2)
