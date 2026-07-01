"""
Tests for Two-Tier Cryptographic Sealing Architecture.

PRIORITY: These tests exist because cryptographic integrity is the foundation
of trust in the Capsule system. If signatures fail, the entire audit trail
is worthless.

ARCHITECTURE:
    Tier 1 (Ed25519, REQUIRED): Classical signatures — always available
    Tier 2 (Ed25519 + ML-DSA-65, OPTIONAL): Adds post-quantum protection
        Install with: pip install qp-capsule[pq]

STRESSOR: These tests strengthen the system by verifying signature invariants
under both tiers, random inputs, and error conditions.
"""

import tempfile
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from qp_capsule import Capsule, Seal, SealError, TriggerSection
from qp_capsule.seal import SealVerifyCode

_pq_installed = False
try:
    import oqs  # noqa: F401
    _pq_installed = True
except ImportError:
    pass

requires_pq = pytest.mark.skipif(
    not _pq_installed,
    reason="requires liboqs (pip install qp-capsule[pq])",
)

# =============================================================================
# TIER 1: Ed25519-Only Mode (Default without PQ)
# =============================================================================


class TestTier1Ed25519Only:
    """
    Ed25519-only sealing is the default when oqs is not installed.
    Every user gets at minimum Ed25519 cryptographic proof.
    """

    def test_seal_without_pq_creates_ed25519_signature(self):
        """
        Sealing with PQ disabled creates Ed25519 signature only.

        SIGNAL: If this fails, Ed25519-only mode is broken.
        """
        capsule = Capsule(
            trigger=TriggerSection(
                type="user_request",
                source="test_user",
                request="Test request",
            )
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=False)

            seal.seal(capsule)

            assert capsule.is_sealed(), "Capsule should be sealed with Ed25519 only"
            assert capsule.hash != "", "Hash must be set"
            assert capsule.signature != "", "Ed25519 signature must be set"
            assert capsule.signature_pq == "", "PQ signature must be empty when PQ disabled"

    def test_is_sealed_true_without_pq_signature(self):
        """
        is_sealed() returns True with only Ed25519 signature.

        This is the key behavior change: is_sealed() no longer requires PQ.

        SIGNAL: If this fails, Ed25519-only Capsules cannot be used.
        """
        capsule = Capsule()

        # Set hash and Ed25519 signature only
        capsule.hash = "a" * 64
        capsule.signature = "b" * 128
        capsule.signature_pq = ""

        assert capsule.is_sealed(), "Capsule with Ed25519 only should be sealed"

    def test_has_pq_seal_false_without_pq(self):
        """
        has_pq_seal() returns False when PQ signature is missing.

        SIGNAL: If this fails, has_pq_seal() doesn't distinguish tiers.
        """
        capsule = Capsule()

        capsule.hash = "a" * 64
        capsule.signature = "b" * 128
        capsule.signature_pq = ""

        assert capsule.is_sealed(), "Should be sealed (Ed25519)"
        assert not capsule.has_pq_seal(), "Should NOT have PQ seal"

    def test_verify_ed25519_only_capsule(self):
        """
        Verification works on Ed25519-only Capsules.

        SIGNAL: If this fails, Ed25519 verification is broken.
        """
        capsule = Capsule(
            trigger=TriggerSection(
                type="user_request",
                source="test_user",
                request="Verify me",
            )
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=False)
            seal.seal(capsule)

            assert seal.verify(capsule) is True

    def test_seal_pq_disabled_ignores_oqs(self):
        """
        With enable_pq=False, oqs is never called even if available.

        SIGNAL: If this fails, PQ is not truly optional.
        """
        capsule = Capsule()

        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=False)

            assert seal.pq_enabled is False

            seal.seal(capsule)

            assert capsule.is_sealed()
            assert capsule.signature_pq == ""

    def test_pq_enabled_false_when_disabled(self):
        """pq_enabled is False when explicitly disabled."""
        with tempfile.TemporaryDirectory() as tmpdir:
            seal_no_pq = Seal(key_path=Path(tmpdir) / "key", enable_pq=False)
            assert seal_no_pq.pq_enabled is False

    @requires_pq
    def test_pq_enabled_true_when_available(self):
        """pq_enabled auto-detects to True when oqs is installed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            seal_auto = Seal(key_path=Path(tmpdir) / "key")
            assert seal_auto.pq_enabled is True


# =============================================================================
# TIER 2: Dual Signature Mode (Ed25519 + ML-DSA-65)
# =============================================================================


@requires_pq
class TestTier2DualSignature:
    """
    Dual signature sealing provides both classical and post-quantum protection.
    Available when oqs library is installed (pip install qp-capsule[pq]).
    """

    def test_seal_creates_both_signatures(self):
        """
        Sealing with PQ enabled creates both Ed25519 and ML-DSA-65 signatures.

        SIGNAL: If this fails, dual-signature sealing is broken.
        """
        capsule = Capsule(
            trigger=TriggerSection(
                type="user_request",
                source="test_user",
                request="Test request",
            )
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=True)
            seal.seal(capsule)

            assert capsule.is_sealed(), "Capsule should be sealed"
            assert capsule.signature != "", "Ed25519 signature must be set"
            assert capsule.signature_pq != "", "ML-DSA-65 signature must be set"

    def test_has_pq_seal_true_with_both(self):
        """
        has_pq_seal() returns True when both signatures present.

        SIGNAL: If this fails, has_pq_seal() detection is broken.
        """
        capsule = Capsule()

        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=True)
            seal.seal(capsule)

            assert capsule.has_pq_seal(), "Should have PQ seal with both signatures"


@requires_pq
class TestPQSignatureVerification:
    """
    Genuine ML-DSA-65 verification: a tampered signature_pq must be rejected,
    and fail-closed (require_pq) mode must demand a real PQ proof.
    """

    def test_valid_pq_signature_verifies(self):
        """A real dual-sealed capsule passes both verify_pq and require_pq."""
        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=True)
            capsule = Capsule(
                trigger=TriggerSection(type="test", source="test", request="PQ proof")
            )
            seal.seal(capsule)

            assert capsule.signature_pq != ""
            assert seal.verify(capsule, verify_pq=True) is True
            assert seal.verify(capsule, require_pq=True) is True

    def test_flipped_pq_signature_fails_verification(self):
        """
        Flipping a byte of signature_pq must break ML-DSA-65 verification.

        SIGNAL: This is the cryptographic regression guard. If a tampered
        post-quantum signature still verifies, the PQ tier is decorative.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=True)
            capsule = Capsule(
                trigger=TriggerSection(type="test", source="test", request="Tamper PQ")
            )
            seal.seal(capsule)

            original = capsule.signature_pq
            assert original != ""

            # Ed25519 + hash are untouched, so structural verify still passes.
            assert seal.verify(capsule, verify_pq=False) is True

            # Flip the first hex nibble of the PQ signature.
            flipped_first = "f" if original[0] != "f" else "0"
            tampered = flipped_first + original[1:]
            assert tampered != original
            capsule.signature_pq = tampered

            # Genuine ML-DSA-65 verification must now fail.
            result = seal.verify_detailed(capsule, verify_pq=True)
            assert result.ok is False
            assert result.code == SealVerifyCode.PQ_VERIFICATION_FAILED
            assert seal.verify(capsule, verify_pq=True) is False
            assert seal.verify(capsule, require_pq=True) is False

    def test_require_pq_passes_for_real_dual_seal(self):
        """require_pq=True returns True only for a genuine ML-DSA-65 seal."""
        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=True)
            capsule = Capsule()
            seal.seal(capsule)
            r = seal.verify_detailed(capsule, require_pq=True)
            assert r.ok is True
            assert r.code == SealVerifyCode.OK


class TestPQRequirementEnforced:
    """Tests that run WITHOUT liboqs to verify error handling."""

    def test_enable_pq_true_raises_without_oqs(self):
        """
        Seal(enable_pq=True) raises SealError if oqs is not available.

        SIGNAL: If this fails, PQ requirement is not enforced.
        """
        with (
            patch("qp_capsule.seal._pq_available", return_value=False),
            pytest.raises(SealError, match="oqs library not available"),
        ):
            Seal(enable_pq=True)


# =============================================================================
# PQ KEY PERSISTENCE
# =============================================================================


@requires_pq
class TestPQKeyPersistence:
    """
    ML-DSA-65 keys must be persisted and reused across Seal instances.
    This was the critical gap in the old architecture.
    """

    def test_pq_keys_persisted_to_disk(self):
        """
        PQ keys are saved to key.ml and key.ml.pub files.

        SIGNAL: If this fails, PQ keys are not being persisted.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "key"
            seal = Seal(key_path=key_path, enable_pq=True)

            capsule = Capsule()
            seal.seal(capsule)

            pq_secret = Path(tmpdir) / "key.ml"
            pq_public = Path(tmpdir) / "key.ml.pub"

            assert pq_secret.exists(), "PQ secret key must be saved to key.ml"
            assert pq_public.exists(), "PQ public key must be saved to key.ml.pub"

    def test_pq_secret_key_restricted_permissions(self):
        """
        PQ secret key has owner-only permissions (0o600).

        SIGNAL: If this fails, PQ keys have unsafe permissions.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "key"
            seal = Seal(key_path=key_path, enable_pq=True)

            capsule = Capsule()
            seal.seal(capsule)

            pq_secret = Path(tmpdir) / "key.ml"
            mode = pq_secret.stat().st_mode & 0o777
            assert mode == 0o600, f"PQ secret key should be 0o600, got {oct(mode)}"

    def test_pq_keys_reused_across_instances(self):
        """
        Second Seal instance loads existing PQ keys instead of regenerating.

        This is the critical fix: the old code generated a new keypair per call,
        making verification impossible.

        SIGNAL: If this fails, PQ key persistence is broken.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "key"

            # First instance generates and persists keys
            seal1 = Seal(key_path=key_path, enable_pq=True)
            capsule1 = Capsule()
            seal1.seal(capsule1)

            pq_secret_1 = (Path(tmpdir) / "key.ml").read_bytes()

            # Second instance should load the same keys
            seal2 = Seal(key_path=key_path, enable_pq=True)
            capsule2 = Capsule()
            seal2.seal(capsule2)

            pq_secret_2 = (Path(tmpdir) / "key.ml").read_bytes()

            assert pq_secret_1 == pq_secret_2, "PQ keys must be the same across instances"


# =============================================================================
# CROSS-INSTANCE VERIFICATION
# =============================================================================


class TestCrossInstanceVerification:
    """
    Capsules sealed by one Seal instance must be verifiable by another
    with the same keys.
    """

    def test_ed25519_cross_instance_verify(self):
        """
        Ed25519 verification works across Seal instances with same key.

        SIGNAL: If this fails, key-based verification is broken.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "key"

            seal1 = Seal(key_path=key_path, enable_pq=False)
            capsule = Capsule(
                trigger=TriggerSection(type="test", source="test", request="Cross-verify")
            )
            seal1.seal(capsule)

            # New instance, same key path
            seal2 = Seal(key_path=key_path, enable_pq=False)
            assert seal2.verify(capsule) is True

    def test_ed25519_verify_with_public_key(self):
        """
        Can verify Ed25519 using only the public key hex.

        SIGNAL: If this fails, public-key-only verification is broken.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "key"

            seal1 = Seal(key_path=key_path, enable_pq=False)
            capsule = Capsule(
                trigger=TriggerSection(type="test", source="test", request="Verify me")
            )
            seal1.seal(capsule)
            public_key = seal1.get_public_key()

            # Completely different Seal instance, different key
            with tempfile.TemporaryDirectory() as tmpdir2:
                seal2 = Seal(key_path=Path(tmpdir2) / "other_key", enable_pq=False)
                assert seal2.verify_with_key(capsule, public_key) is True

    def test_wrong_key_fails_verification(self):
        """
        Verification with wrong key fails.

        SIGNAL: If this fails, signatures can be forged.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            seal1 = Seal(key_path=Path(tmpdir) / "key1", enable_pq=False)
            capsule = Capsule(
                trigger=TriggerSection(type="test", source="test", request="Sealed by key1")
            )
            seal1.seal(capsule)

            # Different key
            seal2 = Seal(key_path=Path(tmpdir) / "key2", enable_pq=False)
            assert seal2.verify(capsule) is False


# =============================================================================
# TAMPERING DETECTION
# =============================================================================


class TestTamperingDetection:
    """
    Tampered Capsules must be detected regardless of tier.
    """

    def test_tampered_content_detected(self):
        """Content tampering breaks the hash."""
        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=False)
            capsule = Capsule(
                trigger=TriggerSection(type="test", source="test", request="Original")
            )
            seal.seal(capsule)

            capsule.trigger.request = "TAMPERED"
            assert seal.verify(capsule) is False

    def test_tampered_hash_detected(self):
        """Hash tampering is caught by signature verification."""
        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=False)
            capsule = Capsule()
            seal.seal(capsule)

            capsule.hash = "f" * 64
            assert seal.verify(capsule) is False

    def test_tampered_signature_detected(self):
        """Signature tampering is caught."""
        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=False)
            capsule = Capsule()
            seal.seal(capsule)

            capsule.signature = "0" * len(capsule.signature)
            assert seal.verify(capsule) is False


# =============================================================================
# SIGNATURE FIELD API CONTRACTS
# =============================================================================


class TestSignatureFieldContracts:
    """
    API contracts for signature fields.
    """

    def test_capsule_has_both_signature_fields(self):
        """
        API CONTRACT: Capsule has signature and signature_pq fields.

        SIGNAL: If this fails, field names have changed (breaking change).
        """
        capsule = Capsule()

        assert hasattr(capsule, "signature"), "Must have 'signature' field"
        assert hasattr(capsule, "signature_pq"), "Must have 'signature_pq' field"
        assert capsule.signature == "", "signature default must be empty string"
        assert capsule.signature_pq == "", "signature_pq default must be empty string"

    def test_seal_accepts_enable_pq_parameter(self):
        """
        API CONTRACT: Seal() accepts enable_pq parameter.

        SIGNAL: If this fails, two-tier API has changed.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            Seal(key_path=Path(tmpdir) / "key1", enable_pq=False)
            Seal(key_path=Path(tmpdir) / "key3", enable_pq=None)
            Seal(key_path=Path(tmpdir) / "key4")  # Default (auto-detect)

    @requires_pq
    def test_seal_accepts_enable_pq_true(self):
        """enable_pq=True works when oqs is installed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Seal(key_path=Path(tmpdir) / "key", enable_pq=True)

    def test_verify_method_accepts_verify_pq(self):
        """
        API CONTRACT: verify() accepts verify_pq parameter.

        SIGNAL: If this fails, verify() signature has changed.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=False)
            capsule = Capsule()
            seal.seal(capsule)

            # These should not raise TypeError
            seal.verify(capsule)
            seal.verify(capsule, verify_pq=False)
            seal.verify(capsule, verify_pq=True)


# =============================================================================
# INVARIANTS
# =============================================================================


class TestSignatureInvariants:
    """
    Properties that must always hold regardless of tier.
    """

    def test_hash_is_deterministic(self):
        """
        INVARIANT: Same content produces same hash.

        SIGNAL: If this fails, content hashing is non-deterministic.
        """
        fixed_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)

        capsule1 = Capsule(
            trigger=TriggerSection(type="test", source="test", request="Same", timestamp=fixed_time)
        )

        capsule2 = Capsule(
            trigger=TriggerSection(type="test", source="test", request="Same", timestamp=fixed_time)
        )
        capsule2.id = capsule1.id  # Force same ID

        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=False)
            seal.seal(capsule1)

            capsule2_copy = Capsule.from_dict(capsule1.to_dict())
            capsule2_copy.hash = ""
            capsule2_copy.signature = ""
            capsule2_copy.signature_pq = ""
            capsule2_copy.signed_at = None
            capsule2_copy.signed_by = ""

            seal.seal(capsule2_copy)

            assert capsule1.hash == capsule2_copy.hash

    def test_seal_sets_metadata(self):
        """
        INVARIANT: Sealing sets signed_at and signed_by.
        """
        capsule = Capsule()

        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=False)
            seal.seal(capsule)

            assert capsule.signed_at is not None
            assert capsule.signed_by != ""
            assert len(capsule.signed_by) == 16  # 16-char fingerprint
