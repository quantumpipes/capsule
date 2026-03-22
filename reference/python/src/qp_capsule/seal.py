# Copyright 2026 Quantum Pipes Technologies, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Patent Pending — See PATENTS.md for details.
# Licensed under the Apache License, Version 2.0 with patent grant (Section 3).

"""
Seal: Cryptographic proof.

Every Capsule is cryptographically sealed to ensure:
    - Integrity: Content cannot be modified without detection
    - Authenticity: Origin can be verified
    - Non-repudiation: Signer cannot deny signing

Two-Tier Cryptographic Architecture:

    Tier 1 — Ed25519 (Classical, REQUIRED):
        - SHA3-256 for content hashing (tamper-evident)
        - Ed25519 for digital signatures (classical, REQUIRED)
        - Available on all platforms via PyNaCl

    Tier 2 — Ed25519 + ML-DSA-65 (Post-Quantum, OPTIONAL):
        - Everything in Tier 1, PLUS
        - ML-DSA-65/Dilithium3 for post-quantum signatures
        - Requires: pip install qp-capsule[pq]
        - Both keys are persisted and reused for verification

    Install post-quantum support:
        pip install qp-capsule[pq]
"""

from __future__ import annotations

import hashlib
import json
import os
import types
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from qp_capsule.exceptions import SealError
from qp_capsule.paths import default_key_path

if TYPE_CHECKING:
    from qp_capsule.capsule import Capsule
    from qp_capsule.keyring import Keyring

# Optional post-quantum cryptography (FIPS 204 ML-DSA-65).
# Available when installed with: pip install qp-capsule[pq]
try:
    import oqs as _oqs_module  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover
    _oqs_module: types.ModuleType | None = None  # type: ignore[no-redef]


def _pq_available() -> bool:
    """Check if post-quantum cryptography is available."""
    return _oqs_module is not None


class SealVerifyCode(StrEnum):
    """Machine-readable result of :meth:`Seal.verify_detailed`."""

    OK = "ok"
    MISSING_HASH = "missing_hash"
    MISSING_SIGNATURE = "missing_signature"
    MALFORMED_HEX = "malformed_hex"
    HASH_MISMATCH = "hash_mismatch"
    INVALID_SIGNATURE = "invalid_signature"
    PQ_VERIFICATION_FAILED = "pq_verification_failed"
    PQ_LIBRARY_UNAVAILABLE = "pq_library_unavailable"
    UNSUPPORTED_ALGORITHM = "unsupported_algorithm"


@dataclass(frozen=True)
class SealVerificationResult:
    """Structured outcome of verify_detailed / verify_with_key_detailed."""

    ok: bool
    code: SealVerifyCode
    message: str = ""

    @property
    def success(self) -> bool:
        return self.ok


def _try_hex_bytes(
    value: str,
    expected_len: int | None,
) -> tuple[bytes, SealVerificationResult | None]:
    """
    Parse hex string to bytes.

    Returns:
        (bytes, None) on success, or (_, error) on failure.
    """
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return (
            b"",
            SealVerificationResult(
                False,
                SealVerifyCode.MALFORMED_HEX,
                "value is not valid hexadecimal",
            ),
        )
    if expected_len is not None and len(raw) != expected_len:
        return (
            b"",
            SealVerificationResult(
                False,
                SealVerifyCode.MALFORMED_HEX,
                f"expected {expected_len} bytes after decoding hex",
            ),
        )
    return raw, None


class Seal:
    """
    Cryptographic sealing for Capsules.

    Two-tier architecture:
        Tier 1 (default): Ed25519 signatures — proven classical security
        Tier 2 (with [pq]): Ed25519 + ML-DSA-65 — adds quantum resistance

    Key Management:
        - Ed25519 keys: ~/.quantumpipes/key (always)
        - ML-DSA-65 keys: ~/.quantumpipes/key.ml + key.ml.pub (when PQ available)
        - All keys generated on first use
        - Permissions restricted to owner (0o600)
    """

    def __init__(
        self,
        key_path: Path | None = None,
        enable_pq: bool | None = None,
        *,
        keyring: Keyring | None = None,
    ):
        """
        Initialize the Seal.

        Args:
            key_path: Path to the Ed25519 private key file.
                      Defaults to $QUANTUMPIPES_DATA_DIR/key or ~/.quantumpipes/key
            enable_pq: Whether to use post-quantum signatures.
                       None = auto-detect (use if oqs library is available)
                       True = require PQ (raises if unavailable)
                       False = disable PQ even if available
            keyring: Optional Keyring for epoch-aware verification.
                     When provided, verify() uses the capsule's signed_by
                     fingerprint to look up the correct epoch's public key.
        """
        self.key_path = key_path or default_key_path()
        self._signing_key: SigningKey | None = None
        self._verify_key: VerifyKey | None = None
        self._keyring = keyring

        # PQ state
        self._pq_secret_key: bytes | None = None
        self._pq_public_key: bytes | None = None

        # Determine PQ mode
        if enable_pq is True:
            if not _pq_available():
                raise SealError(
                    "Post-quantum signatures requested but oqs library not available. "
                    "Install with: pip install qp-capsule[pq]"
                )
            self._pq_enabled = True
        elif enable_pq is False:
            self._pq_enabled = False
        else:
            # Auto-detect
            self._pq_enabled = _pq_available()

    @property
    def pq_enabled(self) -> bool:
        """Whether post-quantum signatures are enabled."""
        return self._pq_enabled

    def _ensure_keys(self) -> tuple[SigningKey, VerifyKey]:
        """
        Load or generate Ed25519 key pair.

        Keys are:
            - Generated with secure random if not exists
            - Stored with restricted permissions (owner only)
            - Loaded from disk on subsequent calls
            - Registered with keyring on first load (if keyring provided)

        Security:
            - Uses umask to ensure file is created with 0o600 permissions
            - No race condition between file creation and permission setting
        """
        if self._signing_key is None:
            if self.key_path.exists():
                # Load existing key
                key_bytes = self.key_path.read_bytes()
                self._signing_key = SigningKey(key_bytes)
            else:
                # Generate new key
                self._signing_key = SigningKey.generate()

                # Save with restricted permissions (using umask to prevent race condition)
                self.key_path.parent.mkdir(parents=True, exist_ok=True)

                # Set restrictive umask before writing, then restore
                old_umask = os.umask(0o077)  # Only owner can read/write
                try:
                    self.key_path.write_bytes(bytes(self._signing_key))
                finally:
                    os.umask(old_umask)

                # Ensure permissions are correct (belt and suspenders)
                self.key_path.chmod(0o600)

            self._verify_key = self._signing_key.verify_key

            if self._keyring is not None:
                self._keyring.register_key(self._signing_key)

        if self._verify_key is None:
            raise SealError("Verify key not initialized")
        return self._signing_key, self._verify_key

    def _ensure_pq_keys(self) -> tuple[bytes, bytes]:
        """
        Load or generate ML-DSA-65 key pair (persistent).

        Keys are stored alongside Ed25519 keys:
            - Secret key: key.ml (same directory as Ed25519 key)
            - Public key: key.ml.pub

        Returns:
            Tuple of (secret_key_bytes, public_key_bytes)

        Raises:
            SealError: If oqs library not available or key operation fails
        """
        if self._pq_secret_key is not None and self._pq_public_key is not None:
            return self._pq_secret_key, self._pq_public_key

        pq_secret_path = self.key_path.parent / "key.ml"
        pq_public_path = self.key_path.parent / "key.ml.pub"

        if _oqs_module is None:
            raise SealError(
                "Post-quantum keys requested but oqs library not available. "
                "Install with: pip install qp-capsule[pq]"
            )

        try:
            if pq_secret_path.exists() and pq_public_path.exists():
                self._pq_secret_key = pq_secret_path.read_bytes()
                self._pq_public_key = pq_public_path.read_bytes()
            else:
                signer = _oqs_module.Signature("ML-DSA-65")

                public_key = signer.generate_keypair()
                secret_key = signer.export_secret_key()

                self.key_path.parent.mkdir(parents=True, exist_ok=True)

                old_umask = os.umask(0o077)
                try:
                    pq_secret_path.write_bytes(secret_key)
                    pq_public_path.write_bytes(public_key)
                finally:
                    os.umask(old_umask)

                pq_secret_path.chmod(0o600)
                pq_public_path.chmod(0o644)

                self._pq_secret_key = secret_key
                self._pq_public_key = public_key

            return self._pq_secret_key, self._pq_public_key

        except SealError:
            raise
        except Exception as e:
            raise SealError(
                f"Failed to load/generate PQ keys: {type(e).__name__}"
            ) from e

    def get_public_key(self) -> str:
        """
        Get the Ed25519 public key as hex string.

        Returns:
            Hex-encoded public key
        """
        _, verify_key = self._ensure_keys()
        return verify_key.encode().hex()

    def get_key_fingerprint(self) -> str:
        """
        Get a short fingerprint of the public key.

        Returns the keyring's ``qp_key_XXXX`` format when a keyring is
        available, otherwise falls back to the legacy 16-char hex prefix.
        """
        if self._keyring is not None:
            active = self._keyring.get_active()
            if active is not None:
                return active.fingerprint
        return self.get_public_key()[:16]

    def seal(self, capsule: Capsule) -> Capsule:
        """
        Seal a Capsule with cryptographic signatures.

        Tier 1 (default): Ed25519 signature only
        Tier 2 (with PQ): Ed25519 + ML-DSA-65 dual signatures

        Process:
            1. Serialize Capsule content to canonical JSON
            2. Hash with SHA3-256
            3. Sign the hash with Ed25519 (classical) — always
            4. Sign the hash with ML-DSA-65 (post-quantum) — if PQ enabled

        Args:
            capsule: The Capsule to seal

        Returns:
            The same Capsule with hash, signature(s), signed_at, signed_by filled

        Raises:
            SealError: If sealing fails
        """
        try:
            signing_key, _ = self._ensure_keys()

            # 1. Serialize to canonical JSON (sorted keys, literal UTF-8)
            content = json.dumps(
                capsule.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
            )

            # 2. Hash with SHA3-256
            hash_value = hashlib.sha3_256(content.encode("utf-8")).hexdigest()

            # 3. Sign the hash with Ed25519 (classical) — ALWAYS
            signed = signing_key.sign(hash_value.encode("utf-8"))
            signature = signed.signature.hex()

            # 4. Sign with ML-DSA-65 (post-quantum) — if PQ enabled
            signature_pq = ""
            if self._pq_enabled:
                pq_sig = self._sign_dilithium(hash_value)
                if pq_sig is None:
                    raise SealError(
                        "Post-quantum signature failed. PQ was enabled but signing returned None."
                    )
                signature_pq = pq_sig

            # 5. Update Capsule
            capsule.hash = hash_value
            capsule.signature = signature
            capsule.signature_pq = signature_pq
            capsule.signed_at = datetime.now(UTC)
            capsule.signed_by = self.get_key_fingerprint()

            return capsule

        except SealError:
            raise
        except Exception as e:
            raise SealError(
                f"Failed to seal Capsule: {type(e).__name__}"
            ) from e

    def _sign_dilithium(self, hash_value: str) -> str | None:
        """
        Sign with ML-DSA-65 post-quantum algorithm.

        Uses persistent keys from _ensure_pq_keys(). The same secret key
        is used for all signatures, enabling verification with the stored
        public key.

        Algorithm names:
            - FIPS 204 standard name: "ML-DSA-65" (NIST, Aug 2024)
            - Legacy/Round 3 name: "Dilithium3"
            - Security level: Level 3 (~AES-192 equivalent)

        Args:
            hash_value: The hash to sign

        Returns:
            Hex-encoded ML-DSA-65 signature, or None if signing fails
        """
        if _oqs_module is None:  # pragma: no cover
            return None

        try:
            secret_key, _ = self._ensure_pq_keys()
            signer = _oqs_module.Signature("ML-DSA-65", secret_key=secret_key)
            signature: bytes = signer.sign(hash_value.encode("utf-8"))
            return signature.hex()
        except SealError:
            raise
        except Exception:
            return None

    def verify_detailed(self, capsule: Capsule, verify_pq: bool = False) -> SealVerificationResult:
        """
        Verify a sealed Capsule and return a structured result (FR-003).

        Same cryptographic steps as :meth:`verify`, but returns :class:`SealVerificationResult`
        with a :class:`SealVerifyCode` instead of only ``True``/``False``.
        """
        if not capsule.hash:
            return SealVerificationResult(
                False, SealVerifyCode.MISSING_HASH, "capsule has no hash field"
            )
        if not capsule.signature:
            return SealVerificationResult(
                False, SealVerifyCode.MISSING_SIGNATURE, "capsule has no signature field"
            )

        _, herr = _try_hex_bytes(capsule.hash, 32)
        if herr is not None:
            return herr
        _, serr = _try_hex_bytes(capsule.signature, 64)
        if serr is not None:
            return serr

        try:
            content = json.dumps(
                capsule.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
            )
            computed_hash = hashlib.sha3_256(content.encode("utf-8")).hexdigest()
        except Exception as e:
            return SealVerificationResult(
                False,
                SealVerifyCode.HASH_MISMATCH,
                f"could not compute content hash: {e!s}",
            )

        if computed_hash != capsule.hash:
            return SealVerificationResult(
                False,
                SealVerifyCode.HASH_MISMATCH,
                "recomputed hash does not match stored hash",
            )

        try:
            resolve_key: VerifyKey | None = None
            if self._keyring is not None and capsule.signed_by:
                pub_hex = self._keyring.lookup_public_key(capsule.signed_by)
                if pub_hex is not None:
                    resolve_key = VerifyKey(bytes.fromhex(pub_hex))

            if resolve_key is None:
                _, resolve_key = self._ensure_keys()

            resolve_key.verify(
                capsule.hash.encode("utf-8"),
                bytes.fromhex(capsule.signature),
            )
        except BadSignatureError:
            return SealVerificationResult(
                False,
                SealVerifyCode.INVALID_SIGNATURE,
                "Ed25519 signature verification failed",
            )
        except Exception as e:
            return SealVerificationResult(
                False,
                SealVerifyCode.INVALID_SIGNATURE,
                f"Ed25519 verification error: {e!s}",
            )

        if verify_pq and capsule.signature_pq:
            if not self._verify_dilithium(capsule.hash, capsule.signature_pq):
                if _oqs_module is None:
                    return SealVerificationResult(
                        False,
                        SealVerifyCode.PQ_LIBRARY_UNAVAILABLE,
                        "post-quantum verification requested but oqs is not installed",
                    )
                return SealVerificationResult(
                    False,
                    SealVerifyCode.PQ_VERIFICATION_FAILED,
                    "ML-DSA-65 signature verification failed",
                )

        return SealVerificationResult(True, SealVerifyCode.OK, "")

    def verify(self, capsule: Capsule, verify_pq: bool = False) -> bool:
        """
        Verify a sealed Capsule.

        Process:
            1. Check Capsule is sealed (Ed25519 required, PQ depends on mode)
            2. Recompute hash from content
            3. Verify hash matches stored hash
            4. Verify Ed25519 signature (epoch-aware via keyring, or local key)
            5. Verify post-quantum signature (if requested and present)

        When a keyring is configured, the capsule's ``signed_by`` fingerprint
        is used to look up the correct epoch's public key. This enables
        verification of capsules signed across key rotations.

        Args:
            capsule: The Capsule to verify
            verify_pq: If True, also verify post-quantum signature (if present)

        Returns:
            True if seal is valid, False otherwise
        """
        return self.verify_detailed(capsule, verify_pq=verify_pq).ok

    def _verify_dilithium(self, hash_value: str, signature_hex: str) -> bool:
        """
        Verify ML-DSA-65 signature using stored public key.

        Args:
            hash_value: The hash that was signed
            signature_hex: Hex-encoded ML-DSA-65 signature

        Returns:
            True if signature is valid, False otherwise
        """
        if _oqs_module is None:  # pragma: no cover
            return False

        try:
            _, public_key = self._ensure_pq_keys()
            verifier = _oqs_module.Signature("ML-DSA-65")

            signature_bytes = bytes.fromhex(signature_hex)
            message_bytes = hash_value.encode("utf-8")

            is_valid: bool = verifier.verify(message_bytes, signature_bytes, public_key)
            return is_valid
        except Exception:
            return False

    def verify_with_key_detailed(
        self, capsule: Capsule, public_key_hex: str
    ) -> SealVerificationResult:
        """Verify using an explicit Ed25519 public key (structured result, FR-003)."""
        if not capsule.hash:
            return SealVerificationResult(
                False, SealVerifyCode.MISSING_HASH, "capsule has no hash field"
            )
        if not capsule.signature:
            return SealVerificationResult(
                False, SealVerifyCode.MISSING_SIGNATURE, "capsule has no signature field"
            )

        _, herr = _try_hex_bytes(capsule.hash, 32)
        if herr is not None:
            return herr
        _, serr = _try_hex_bytes(capsule.signature, 64)
        if serr is not None:
            return serr

        try:
            content = json.dumps(
                capsule.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
            )
            computed_hash = hashlib.sha3_256(content.encode("utf-8")).hexdigest()
        except Exception as e:
            return SealVerificationResult(
                False,
                SealVerifyCode.HASH_MISMATCH,
                f"could not compute content hash: {e!s}",
            )

        if computed_hash != capsule.hash:
            return SealVerificationResult(
                False,
                SealVerifyCode.HASH_MISMATCH,
                "recomputed hash does not match stored hash",
            )

        pk_raw, pk_err = _try_hex_bytes(public_key_hex, 32)
        if pk_err is not None:
            return pk_err

        try:
            verify_key = VerifyKey(pk_raw)
            verify_key.verify(
                capsule.hash.encode("utf-8"),
                bytes.fromhex(capsule.signature),
            )
        except BadSignatureError:
            return SealVerificationResult(
                False,
                SealVerifyCode.INVALID_SIGNATURE,
                "Ed25519 signature verification failed",
            )
        except Exception as e:
            return SealVerificationResult(
                False,
                SealVerifyCode.INVALID_SIGNATURE,
                f"Ed25519 verification error: {e!s}",
            )

        return SealVerificationResult(True, SealVerifyCode.OK, "")

    def verify_with_key(self, capsule: Capsule, public_key_hex: str) -> bool:
        """
        Verify a Capsule with a specific Ed25519 public key.

        Useful for verifying Capsules sealed by other instances.

        Args:
            capsule: The Capsule to verify
            public_key_hex: Hex-encoded Ed25519 public key

        Returns:
            True if seal is valid, False otherwise
        """
        return self.verify_with_key_detailed(capsule, public_key_hex).ok


def compute_hash(data: dict[str, Any]) -> str:
    """
    Compute SHA3-256 hash of data.

    Utility function for standalone hashing.

    Args:
        data: Dictionary to hash

    Returns:
        Hex-encoded hash
    """
    content = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha3_256(content.encode("utf-8")).hexdigest()
