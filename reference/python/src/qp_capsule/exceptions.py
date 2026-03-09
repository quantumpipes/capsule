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


class StorageError(CapsuleError):
    """Capsule storage operation failed."""


class KeyringError(CapsuleError):
    """Keyring operation failed (load, save, rotate, lookup)."""
