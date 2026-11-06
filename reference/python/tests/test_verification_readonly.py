"""Verification cannot provision keys, migrate custody or replace a partial pair."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from nacl.signing import SigningKey

from qp_capsule import Capsule, Seal
from qp_capsule.exceptions import KeyringError, SealError
from qp_capsule.keyring import Keyring
from qp_capsule.seal import SealVerifyCode


@pytest.fixture
def signed(tmp_path):
    signer = Seal(key_path=tmp_path / "issuer" / "key", enable_pq=False)
    capsule = Capsule()
    signer.seal(capsule)
    return signer, capsule


def _files(root: Path) -> dict[str, bytes]:
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def _pq_verifier(capsule):
    """A deterministic API fixture, not evidence of actual PQ cryptography."""
    oqs = MagicMock()
    oqs.Signature.return_value.verify.side_effect = lambda message, signature, public: (
        message == capsule.hash.encode() and signature == b"signature" and public == b"p" * 1952
    )
    return oqs


def test_missing_verifier_key_does_not_create_a_directory_or_register(signed, tmp_path):
    _, capsule = signed
    root = tmp_path / "unprovisioned"
    ring = Keyring(keyring_path=root / "keyring.json", key_path=root / "key")
    verifier = Seal(key_path=root / "key", keyring=ring, enable_pq=False)
    with patch.object(verifier, "_ensure_keys") as create, patch.object(ring, "_save") as save:
        result = verifier.verify_detailed(capsule)
    assert result.code is SealVerifyCode.INVALID_SIGNATURE
    assert str(root) not in result.message
    assert not root.exists()
    create.assert_not_called()
    save.assert_not_called()


def test_legacy_verification_defers_migration_until_signing(signed):
    signer, capsule = signed
    ring = Keyring(keyring_path=signer.key_path.parent / "keyring.json", key_path=signer.key_path)
    verifier = Seal(key_path=signer.key_path, keyring=ring, enable_pq=False)
    before = _files(signer.key_path.parent)
    with patch.object(ring, "_migrate_existing_key", wraps=ring._migrate_existing_key) as migrate:
        assert verifier.verify(capsule)
        migrate.assert_not_called()
    assert _files(signer.key_path.parent) == before
    # A read must not cache an empty ring in a way that disables later provisioning.
    verifier.seal(Capsule())
    assert ring.path.is_file()
    assert len(ring.epochs) == 1


def test_existing_keyring_verifies_a_retired_epoch_without_private_seed(signed):
    signer, capsule = signed
    ring = Keyring(keyring_path=signer.key_path.parent / "keyring.json", key_path=signer.key_path)
    ring.load()
    ring.rotate()
    signer.key_path.unlink()  # This isolated test created and owns the seed.
    cold_ring = Keyring(keyring_path=ring.path, key_path=signer.key_path)
    verifier = Seal(key_path=signer.key_path, keyring=cold_ring, enable_pq=False)
    before = _files(signer.key_path.parent)
    assert verifier.verify(capsule)
    assert verifier.verify(capsule)  # The loaded public ring remains read-only.
    assert _files(signer.key_path.parent) == before


def test_readonly_keyring_distinguishes_missing_from_unreadable(tmp_path):
    ring = Keyring(keyring_path=tmp_path / "ring.json", key_path=tmp_path / "seed")
    assert ring.lookup_public_key_readonly("unknown") is None
    with patch.object(Path, "stat", side_effect=PermissionError("PRIVATE_PATH")):
        with pytest.raises(KeyringError, match="Cannot inspect verification keyring"):
            ring.lookup_public_key_readonly("unknown")
    assert not ring.path.exists()


def test_readonly_keyring_missing_fingerprint_does_not_mutate(signed):
    signer, _ = signed
    ring = Keyring(keyring_path=signer.key_path.parent / "ring.json", key_path=signer.key_path)
    ring.load()
    cold = Keyring(keyring_path=ring.path, key_path=signer.key_path)
    before = ring.path.read_bytes()
    assert cold.lookup_public_key_readonly("unknown") is None
    assert cold.lookup_public_key_readonly(ring.epochs[0].fingerprint) == signer.get_public_key()
    assert ring.path.read_bytes() == before


@pytest.mark.parametrize("present", ["neither", "secret", "public", "both"])
def test_pq_verification_preserves_each_partial_restore(signed, present):
    signer, capsule = signed
    capsule.signature_pq = b"signature".hex()
    root = signer.key_path.parent
    if present in {"secret", "both"}:
        (root / "key.ml").write_bytes(b"SURVIVING_SECRET_FIXTURE")
    if present in {"public", "both"}:
        (root / "key.ml.pub").write_bytes(b"p" * 1952)
    before = _files(root)
    verifier = Seal(key_path=signer.key_path, enable_pq=False)
    oqs = _pq_verifier(capsule)
    with (
        patch("qp_capsule.seal._oqs_module", oqs),
        patch.object(verifier, "_ensure_pq_keys") as create,
    ):
        result = verifier.verify_detailed(capsule, require_pq=True)
    assert result.ok is (present in {"public", "both"})
    assert _files(root) == before
    create.assert_not_called()
    oqs.Signature.return_value.generate_keypair.assert_not_called()
    oqs.Signature.return_value.export_secret_key.assert_not_called()
    if result.ok:
        oqs.Signature.return_value.free.assert_called_once()


def test_pinned_pair_reads_no_files_and_ignores_unsigned_signer_labels(signed, tmp_path):
    signer, capsule = signed
    public = signer.get_public_key()
    capsule.signature_pq = b"signature".hex()
    capsule.signed_by = "attacker-controlled-hint"
    verifier = Seal(key_path=tmp_path / "absent" / "key", enable_pq=False)
    oqs = _pq_verifier(capsule)
    with (
        patch("qp_capsule.seal._oqs_module", oqs),
        patch.object(Path, "read_bytes") as read,
        patch.object(verifier, "_ensure_keys") as ed_create,
        patch.object(verifier, "_ensure_pq_keys") as pq_create,
    ):
        result = verifier.verify_with_keys_detailed(capsule, public, (b"p" * 1952).hex())
    assert result.ok
    read.assert_not_called()
    ed_create.assert_not_called()
    pq_create.assert_not_called()
    assert not verifier.key_path.parent.exists()
    oqs.Signature.return_value.free.assert_called_once()


@pytest.mark.parametrize(
    "damage,expected",
    [
        ("classical", SealVerifyCode.INVALID_SIGNATURE),
        ("pq", SealVerifyCode.PQ_VERIFICATION_FAILED),
        ("missing_pq", SealVerifyCode.MISSING_PQ_SIGNATURE),
        ("ed_key", SealVerifyCode.INVALID_SIGNATURE),
        ("pq_key", SealVerifyCode.PQ_VERIFICATION_FAILED),
        ("malformed_key", SealVerifyCode.MALFORMED_HEX),
        ("malformed_type", SealVerifyCode.MALFORMED_HEX),
        ("unavailable", SealVerifyCode.PQ_LIBRARY_UNAVAILABLE),
    ],
)
def test_pinned_pair_requires_both_correct_signatures_and_keys(signed, tmp_path, damage, expected):
    signer, capsule = signed
    public = signer.get_public_key()
    pq_public = (b"p" * 1952).hex()
    capsule.signature_pq = b"signature".hex()
    oqs = _pq_verifier(capsule)
    if damage == "classical":
        capsule.signature = "00" * 64
    elif damage == "pq":
        capsule.signature_pq = "00"
    elif damage == "missing_pq":
        capsule.signature_pq = ""
    elif damage == "ed_key":
        public = SigningKey.generate().verify_key.encode().hex()
    elif damage == "pq_key":
        pq_public = (b"w" * 1952).hex()
    elif damage == "malformed_key":
        pq_public = "PRIVATE_NONHEX_INPUT"
    elif damage == "malformed_type":
        pq_public = True
    else:
        oqs = None
    verifier = Seal(key_path=tmp_path / "absent" / "key", enable_pq=False)
    with patch("qp_capsule.seal._oqs_module", oqs):
        result = verifier.verify_with_keys_detailed(capsule, public, pq_public)
    assert not result.ok and result.code is expected
    assert "PRIVATE" not in result.message
    assert not verifier.key_path.parent.exists()


def test_pq_verifier_is_freed_when_signature_decoding_fails(signed):
    signer, capsule = signed
    capsule.signature_pq = "not hex"
    oqs = _pq_verifier(capsule)
    with patch("qp_capsule.seal._oqs_module", oqs):
        result = signer.verify_with_keys_detailed(
            capsule, signer.get_public_key(), (b"p" * 1952).hex()
        )
    assert result.code is SealVerifyCode.PQ_VERIFICATION_FAILED
    oqs.Signature.return_value.free.assert_called_once()


@pytest.mark.parametrize("survivor", ["key.ml", "key.ml.pub"])
def test_signing_refuses_to_replace_an_existing_partial_pq_pair(tmp_path, survivor):
    (tmp_path / survivor).write_bytes(b"SURVIVING_FIXTURE")
    oqs = MagicMock()
    with patch("qp_capsule.seal._oqs_module", oqs):
        signer = Seal(key_path=tmp_path / "key", enable_pq=True)
        before = _files(tmp_path)
        with pytest.raises(SealError, match="Incomplete post-quantum key pair"):
            signer._ensure_pq_keys()
    assert _files(tmp_path) == before
    oqs.Signature.assert_not_called()


@pytest.mark.parametrize("length", [0, 1, 1951, 1953])
def test_pq_pins_have_exact_length_before_native_verification(signed, length):
    signer, capsule = signed
    capsule.signature_pq = b"signature".hex()
    oqs = _pq_verifier(capsule)
    with patch("qp_capsule.seal._oqs_module", oqs):
        result = signer.verify_with_keys_detailed(
            capsule, signer.get_public_key(), (b"p" * length).hex()
        )
        assert result.code is SealVerifyCode.MALFORMED_HEX
        signer._pq_public_key = b"p" * length
        assert not signer.verify_detailed(capsule, require_pq=True).ok
    oqs.Signature.assert_not_called()
