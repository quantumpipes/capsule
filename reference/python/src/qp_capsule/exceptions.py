# Copyright 2026 Quantum Pipes Technologies, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Patent Pending — See PATENTS.md for details.
# Licensed under the Apache License, Version 2.0 with patent grant (Section 3).

"""
Exceptions for the Capsule Protocol Specification (CPS) implementation.
"""


class CapsuleError(Exception):
    """Base exception for capsule operations."""


class SealError(CapsuleError):
    """Sealing or verification failed."""


class ChainError(CapsuleError):
    """Hash chain integrity error."""


class ChainConflictError(ChainError):
    """Concurrent write detected — sequence conflict after max retries."""


class StorageError(CapsuleError):
    """Capsule storage operation failed."""


class ChainHeadMovedError(StorageError):
    """The capsule names a previous hash that is not the stored capsule before it.

    Raised by ``store`` before it commits, so nothing is written. A writer whose head
    went stale, or was read from a connection still holding someone's failed write,
    would otherwise link to a capsule the chain never kept. The chain retries it the
    way it retries a sequence another writer took.
    """


class KeyringError(CapsuleError):
    """Keyring operation failed (load, save, rotate, lookup)."""
