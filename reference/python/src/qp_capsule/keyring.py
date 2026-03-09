# Copyright 2026 Quantum Pipes Technologies, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Patent Pending — See PATENTS.md for details.
# Licensed under the Apache License, Version 2.0 with patent grant (Section 3).

"""
Keyring: Epoch-based key lifecycle management.

Manages Ed25519 key pairs across rotation epochs, enabling:
    - Automated key rotation (NIST SP 800-57 lifecycle)
    - Backward-compatible verification (old capsules verify with old keys)
    - Seamless migration from existing single-key installations

NIST SP 800-57 Alignment:
    Generation: ``capsule keys rotate`` or auto-generate on first seal()
    Active:     Current epoch, used for new capsules
    Retired:    Old epoch, public key retained for verification only
    Destroyed:  Private key securely deleted on rotation

Keyring file: ``~/.quantumpipes/keyring.json``
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nacl.signing import SigningKey

from qp_capsule.exceptions import KeyringError
from qp_capsule.paths import default_key_path, default_keyring_path


def _make_fingerprint(public_key_hex: str) -> str:
    """Create a short fingerprint from a public key hex string."""
    return f"qp_key_{public_key_hex[:4]}"


@dataclass
class Epoch:
    """A single key epoch in the keyring."""

    epoch: int
    algorithm: str
    public_key_hex: str
    fingerprint: str
    created_at: str
    rotated_at: str | None
    status: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "epoch": self.epoch,
            "algorithm": self.algorithm,
            "public_key_hex": self.public_key_hex,
            "fingerprint": self.fingerprint,
            "created_at": self.created_at,
            "rotated_at": self.rotated_at,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Epoch:
        return cls(
            epoch=data["epoch"],
            algorithm=data["algorithm"],
            public_key_hex=data["public_key_hex"],
            fingerprint=data["fingerprint"],
            created_at=data["created_at"],
            rotated_at=data.get("rotated_at"),
            status=data["status"],
        )


class Keyring:
    """
    Epoch-based key lifecycle manager.

    Manages a keyring of Ed25519 key pairs with:
        - Key rotation with epoch tracking
        - Backward-compatible verification via fingerprint lookup
        - Automatic migration from pre-keyring key files
        - Atomic writes for crash safety
    """

    KEYRING_VERSION = 1

    def __init__(
        self,
        keyring_path: Path | None = None,
        key_path: Path | None = None,
    ):
        self._keyring_path = keyring_path or default_keyring_path()
        self._key_path = key_path or default_key_path()
        self._version: int = self.KEYRING_VERSION
        self._active_epoch: int = 0
        self._epochs: list[Epoch] = []
        self._loaded = False

    @property
    def path(self) -> Path:
        """Path to the keyring file."""
        return self._keyring_path

    @property
    def key_path(self) -> Path:
        """Path to the Ed25519 private key file."""
        return self._key_path

    @property
    def active_epoch(self) -> int:
        """The current active epoch number."""
        self._ensure_loaded()
        return self._active_epoch

    @property
    def epochs(self) -> list[Epoch]:
        """All epochs (returns a copy)."""
        self._ensure_loaded()
        return list(self._epochs)

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self.load()

    def load(self) -> None:
        """
        Load keyring from disk, migrating from existing keys if needed.

        Priority:
            1. Load existing keyring.json
            2. Migrate from existing key file (create epoch 0)
            3. Create empty keyring (keys generated on first seal)
        """
        if self._keyring_path.exists():
            self._load_from_file()
        elif self._key_path.exists():
            self._migrate_existing_key()
        else:
            self._version = self.KEYRING_VERSION
            self._active_epoch = 0
            self._epochs = []
        self._loaded = True

    def _load_from_file(self) -> None:
        try:
            data = json.loads(self._keyring_path.read_text("utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            raise KeyringError(f"Failed to read keyring: {e}") from e

        version = data.get("version")
        if version != self.KEYRING_VERSION:
            raise KeyringError(
                f"Unsupported keyring version: {version} "
                f"(expected {self.KEYRING_VERSION})"
            )

        self._version = data["version"]
        self._active_epoch = data["active_epoch"]
        self._epochs = [Epoch.from_dict(e) for e in data.get("epochs", [])]

    def _migrate_existing_key(self) -> None:
        """Create epoch 0 from an existing key file (seamless upgrade)."""
        try:
            key_bytes = self._key_path.read_bytes()
            signing_key = SigningKey(key_bytes)
            public_hex = signing_key.verify_key.encode().hex()
            now = datetime.now(UTC).isoformat()

            self._version = self.KEYRING_VERSION
            self._active_epoch = 0
            self._epochs = [
                Epoch(
                    epoch=0,
                    algorithm="ed25519",
                    public_key_hex=public_hex,
                    fingerprint=_make_fingerprint(public_hex),
                    created_at=now,
                    rotated_at=None,
                    status="active",
                )
            ]
            self._save()
        except KeyringError:
            raise  # pragma: no cover
        except Exception as e:
            raise KeyringError(f"Failed to migrate existing key: {e}") from e

    def _save(self) -> None:
        """Atomically write keyring to disk (write temp, then rename)."""
        data = {
            "version": self._version,
            "active_epoch": self._active_epoch,
            "epochs": [e.to_dict() for e in self._epochs],
        }

        self._keyring_path.parent.mkdir(parents=True, exist_ok=True)

        fd, tmp_path = tempfile.mkstemp(
            dir=str(self._keyring_path.parent),
            suffix=".tmp",
        )
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2)
                f.write("\n")
            os.replace(tmp_path, str(self._keyring_path))
        except Exception:  # pragma: no cover
            with contextlib.suppress(OSError):
                os.unlink(tmp_path)
            raise

    def get_active(self) -> Epoch | None:
        """Get the active epoch, or None if no epochs exist."""
        self._ensure_loaded()
        for epoch in self._epochs:
            if epoch.status == "active":
                return epoch
        return None

    def lookup(self, fingerprint: str) -> Epoch | None:
        """
        Look up an epoch by fingerprint.

        Matches on the ``qp_key_XXXX`` format and on the legacy
        16-char hex prefix used by pre-keyring capsules.
        """
        self._ensure_loaded()
        for epoch in self._epochs:
            if epoch.fingerprint == fingerprint:
                return epoch
        for epoch in self._epochs:
            if epoch.public_key_hex[:16] == fingerprint:
                return epoch
        return None

    def lookup_public_key(self, fingerprint: str) -> str | None:
        """Look up a public key hex string by fingerprint."""
        epoch = self.lookup(fingerprint)
        return epoch.public_key_hex if epoch else None

    def rotate(self) -> Epoch:
        """
        Rotate to a new key pair.

        1. Generate new Ed25519 key pair
        2. Retire current active epoch
        3. Add new epoch as active
        4. Write new private key (securely replaces old)
        5. Save keyring atomically
        """
        self._ensure_loaded()

        now = datetime.now(UTC).isoformat()

        for epoch in self._epochs:
            if epoch.status == "active":
                epoch.rotated_at = now
                epoch.status = "retired"

        new_signing_key = SigningKey.generate()
        public_hex = new_signing_key.verify_key.encode().hex()
        new_epoch_num = (max(e.epoch for e in self._epochs) + 1) if self._epochs else 0

        new_epoch = Epoch(
            epoch=new_epoch_num,
            algorithm="ed25519",
            public_key_hex=public_hex,
            fingerprint=_make_fingerprint(public_hex),
            created_at=now,
            rotated_at=None,
            status="active",
        )

        self._epochs.append(new_epoch)
        self._active_epoch = new_epoch_num

        self._key_path.parent.mkdir(parents=True, exist_ok=True)
        old_umask = os.umask(0o077)
        try:
            self._key_path.write_bytes(bytes(new_signing_key))
        finally:
            os.umask(old_umask)
        self._key_path.chmod(0o600)

        self._save()
        return new_epoch

    def register_key(self, signing_key: SigningKey) -> Epoch:
        """
        Register an existing key in the keyring. Idempotent.

        Called by Seal when generating a key for a keyring that
        does not yet track it.
        """
        self._ensure_loaded()

        public_hex = signing_key.verify_key.encode().hex()

        for epoch in self._epochs:
            if epoch.public_key_hex == public_hex:
                return epoch

        new_epoch_num = (max(e.epoch for e in self._epochs) + 1) if self._epochs else 0
        now = datetime.now(UTC).isoformat()

        epoch = Epoch(
            epoch=new_epoch_num,
            algorithm="ed25519",
            public_key_hex=public_hex,
            fingerprint=_make_fingerprint(public_hex),
            created_at=now,
            rotated_at=None,
            status="active",
        )

        self._epochs.append(epoch)
        self._active_epoch = new_epoch_num
        self._save()
        return epoch

    def export_public_key(self) -> str | None:
        """Export the active epoch's public key as a hex string."""
        active = self.get_active()
        return active.public_key_hex if active else None

    def to_dict(self) -> dict[str, Any]:
        """Serialize keyring to dict."""
        self._ensure_loaded()
        return {
            "version": self._version,
            "active_epoch": self._active_epoch,
            "epochs": [e.to_dict() for e in self._epochs],
        }
