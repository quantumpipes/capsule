# Copyright 2026 Quantum Pipes Technologies, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Patent Pending — See PATENTS.md for details.
# Licensed under the Apache License, Version 2.0 with patent grant (Section 3).

"""
Capsule: The Capsule Protocol Specification (CPS) reference implementation.

Every AI action is sealed in a Capsule — a tamper-proof, cryptographically
signed record with six sections capturing what happened, why, and who approved it.

    pip install qp-capsule              # Create, seal, verify (Ed25519)
    pip install qp-capsule[storage]     # + SQLite persistence
    pip install qp-capsule[postgres]    # + PostgreSQL persistence
    pip install qp-capsule[pq]          # + Post-quantum signatures (ML-DSA-65)

Quick start:

    from qp_capsule import Capsule, Seal, CapsuleType, TriggerSection

    capsule = Capsule(
        type=CapsuleType.AGENT,
        trigger=TriggerSection(
            type="user_request",
            source="deploy-bot",
            request="Deploy service v2.4 to production",
        ),
    )

    seal = Seal()
    seal.seal(capsule)
    assert seal.verify(capsule)

Cross-language SDKs: Python, TypeScript, Go, Rust
Spec: https://github.com/quantumpipes/capsule
"""

__version__ = "1.5.2"
__author__ = "Quantum Pipes Technologies, LLC"
__license__ = "Apache-2.0"

import contextlib

from qp_capsule.capsule import (
    AuthoritySection,
    Capsule,
    CapsuleType,
    ContextSection,
    ExecutionSection,
    OutcomeSection,
    ReasoningOption,
    ReasoningSection,
    ToolCall,
    TriggerSection,
)
from qp_capsule.exceptions import (
    CapsuleError,
    ChainConflictError,
    ChainError,
    KeyringError,
    SealError,
    StorageError,
)
from qp_capsule.keyring import Epoch, Keyring
from qp_capsule.protocol import CapsuleStorageProtocol
from qp_capsule.seal import Seal, compute_hash

with contextlib.suppress(ImportError):
    from qp_capsule.chain import CapsuleChain, ChainVerificationResult

with contextlib.suppress(ImportError):
    from qp_capsule.storage import CapsuleStorage

with contextlib.suppress(ImportError):
    from qp_capsule.storage_pg import CapsuleStoragePG, PostgresCapsuleStorage

from qp_capsule.audit import Capsules

__all__ = [
    # Version
    "__version__",
    # Capsule
    "Capsule",
    "CapsuleType",
    "TriggerSection",
    "ContextSection",
    "ReasoningOption",
    "ReasoningSection",
    "AuthoritySection",
    "ExecutionSection",
    "OutcomeSection",
    "ToolCall",
    # Seal
    "Seal",
    "compute_hash",
    # Keyring
    "Keyring",
    "Epoch",
    # Protocol
    "CapsuleStorageProtocol",
    # Chain
    "CapsuleChain",
    "ChainVerificationResult",
    # Storage
    "CapsuleStorage",
    "PostgresCapsuleStorage",
    "CapsuleStoragePG",
    # Exceptions
    "CapsuleError",
    "SealError",
    "ChainError",
    "ChainConflictError",
    "StorageError",
    "KeyringError",
    # High-Level API
    "Capsules",
]
