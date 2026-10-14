# Copyright 2026 Quantum Pipes Technologies, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Patent Pending — See PATENTS.md for details.
# Licensed under the Apache License, Version 2.0 with patent grant (Section 3).

"""
Chain: Temporal integrity.

Each Capsule links to the previous via hash, forming an unbroken chain.
Like blockchain, but without the bloat.

Properties:
    - Tamper-evident: Modifying any Capsule breaks the chain
    - Temporal ordering: Provable sequence of events
    - Integrity verification: Anyone can verify the chain

The chain is the memory of the system made immutable.

Concurrency:
    seal_and_store() uses optimistic retry — if a concurrent writer claims
    the same sequence number, the UNIQUE constraint rejects the duplicate
    and the method retries with the updated chain head.
"""

from __future__ import annotations

import asyncio
import logging
import random
import weakref
from dataclasses import dataclass
from typing import TYPE_CHECKING

from qp_capsule.capsule import content_for_hash
from qp_capsule.exceptions import ChainConflictError
from qp_capsule.seal import compute_hash

if TYPE_CHECKING:
    from qp_capsule.capsule import Capsule
    from qp_capsule.protocol import CapsuleStorageProtocol
    from qp_capsule.seal import Seal

_log = logging.getLogger(__name__)

_MAX_CHAIN_RETRIES = 3

# Upper bound, in seconds, of the random wait before retry N (scaled by N).
# Only writers in OTHER processes reach a retry once the in-process lock below
# is held, so this spreads them apart instead of re-colliding on the next tick.
_RETRY_JITTER_S = 0.05

# One lock per (event loop, storage target). Writers in one process used to
# race each other through read-head, seal, store: at AskQP desktop startup
# five producers emitted at once, each round only one won, and the fourth and
# fifth losers exhausted three retries and dropped their audit records
# (`ChainConflictError`, measured 2026-10-14 in launch after launch). Holding
# a lock across the whole sequence turns that race into a queue.
_chain_locks: weakref.WeakKeyDictionary[
    asyncio.AbstractEventLoop, dict[object, asyncio.Lock]
] = weakref.WeakKeyDictionary()


def _storage_key(storage: object) -> object:
    """Identify the database a storage writes to, not the Python object.

    Several storage objects may point at one database (a service that builds
    its own, a request-scoped one), and they share one chain, so they must
    share one lock. Falls back to object identity when the target is unknown.
    """
    for attr in ("database_url", "db_path"):
        target = getattr(storage, attr, None)
        if target is not None:
            return (attr, str(target))
    return ("id", id(storage))


def _chain_lock(storage: object) -> asyncio.Lock:
    """The lock that serializes chain writes to ``storage`` on this loop."""
    loop = asyncio.get_running_loop()
    locks = _chain_locks.setdefault(loop, {})
    key = _storage_key(storage)
    lock = locks.get(key)
    if lock is None:
        lock = locks[key] = asyncio.Lock()
    return lock


@dataclass
class ChainVerificationResult:
    """Result of chain verification."""

    valid: bool
    error: str | None = None
    broken_at: str | None = None  # Capsule ID where chain broke
    capsules_verified: int = 0


class CapsuleChain:
    """
    Hash chain for Capsules.

    Each Capsule contains:
        - Its own hash (SHA3-256 of contents)
        - The previous Capsule's hash
        - A sequence number

    This creates:
        - Tamper evidence: Change one Capsule, break the chain
        - Temporal ordering: Provable sequence of events
        - Integrity verification: Anyone can verify the chain
    """

    def __init__(self, storage: CapsuleStorageProtocol):
        """
        Initialize the chain.

        Args:
            storage: Any storage backend satisfying CapsuleStorageProtocol
        """
        self.storage = storage

    async def add(self, capsule: Capsule, tenant_id: str | None = None) -> Capsule:
        """
        Add a Capsule to the chain.

        Sets previous_hash and sequence based on the current chain head.
        Does NOT seal or store the Capsule - that's done separately.

        Args:
            capsule: The Capsule to add
            tenant_id: Optional tenant for per-tenant chains

        Returns:
            The Capsule with previous_hash and sequence set
        """
        latest = await self.storage.get_latest(tenant_id=tenant_id)

        if latest:
            capsule.previous_hash = latest.hash
            capsule.sequence = latest.sequence + 1
        else:
            capsule.previous_hash = None
            capsule.sequence = 0

        return capsule

    async def verify(
        self,
        tenant_id: str | None = None,
        *,
        verify_content: bool = False,
        seal: Seal | None = None,
    ) -> ChainVerificationResult:
        """
        Verify the entire chain integrity.

        Structural checks (always):
            1. Sequence numbers are consecutive (0, 1, 2, ...)
            2. Each Capsule's previous_hash matches the previous Capsule's hash
            3. First Capsule has previous_hash = None

        Cryptographic checks (when verify_content=True or seal is provided):
            4. Recompute SHA3-256 from content and compare to stored hash
            5. Verify Ed25519 signature (requires seal)

        Args:
            tenant_id: If provided, verify only this tenant's chain
            verify_content: If True, recompute hashes from content
            seal: If provided, also verify Ed25519 signatures (implies verify_content)

        Returns:
            ChainVerificationResult with validity and error details
        """
        if seal is not None:
            verify_content = True

        capsules = await self.storage.get_all_ordered(tenant_id=tenant_id)

        if not capsules:
            return ChainVerificationResult(valid=True, capsules_verified=0)

        for i, capsule in enumerate(capsules):
            # Check sequence number
            if capsule.sequence != i:
                return ChainVerificationResult(
                    valid=False,
                    error=f"Sequence gap: expected {i}, got {capsule.sequence}",
                    broken_at=str(capsule.id),
                    capsules_verified=i,
                )

            # Check previous_hash
            if i == 0:
                if capsule.previous_hash is not None:
                    return ChainVerificationResult(
                        valid=False,
                        error="Genesis Capsule has previous_hash (should be None)",
                        broken_at=str(capsule.id),
                        capsules_verified=0,
                    )
            else:
                expected_prev = capsules[i - 1].hash
                if capsule.previous_hash != expected_prev:
                    return ChainVerificationResult(
                        valid=False,
                        error=f"Chain broken: previous_hash mismatch at sequence {i}",
                        broken_at=str(capsule.id),
                        capsules_verified=i,
                    )

            if verify_content:
                # Hash the stored document (CPS Section 3.5), never a re-serialized model.
                try:
                    document = content_for_hash(capsule)
                    matches = document is not None and compute_hash(document) == capsule.hash
                except (RecursionError, TypeError, ValueError):
                    matches = False
                if not matches:
                    return ChainVerificationResult(
                        valid=False,
                        error=f"Content hash mismatch at sequence {i}",
                        broken_at=str(capsule.id),
                        capsules_verified=i,
                    )

            if seal is not None and not seal.verify(capsule):
                return ChainVerificationResult(
                    valid=False,
                    error=f"Signature verification failed at sequence {i}",
                    broken_at=str(capsule.id),
                    capsules_verified=i,
                )

        return ChainVerificationResult(
            valid=True,
            capsules_verified=len(capsules),
        )

    async def verify_capsule_in_chain(
        self, capsule: Capsule, tenant_id: str | None = None
    ) -> bool:
        """
        Verify a single Capsule is properly linked in the chain.

        Args:
            capsule: The Capsule to verify
            tenant_id: If provided, verify within this tenant's chain

        Returns:
            True if Capsule is properly linked
        """
        if capsule.sequence == 0:
            # Genesis Capsule
            return capsule.previous_hash is None

        # Get the previous Capsule
        capsules = await self.storage.get_all_ordered(tenant_id=tenant_id)
        if capsule.sequence >= len(capsules):
            return False

        if capsule.sequence > 0:
            previous = capsules[capsule.sequence - 1]
            return capsule.previous_hash == previous.hash

        return True  # pragma: no cover

    async def get_chain_length(self, tenant_id: str | None = None) -> int:
        """
        Get the current chain length.

        Args:
            tenant_id: If provided, returns length for this tenant's chain

        Returns:
            Number of Capsules in the chain
        """
        latest = await self.storage.get_latest(tenant_id=tenant_id)
        if latest:
            return latest.sequence + 1
        return 0

    async def get_chain_head(self, tenant_id: str | None = None) -> Capsule | None:
        """
        Get the most recent Capsule (chain head).

        Args:
            tenant_id: If provided, returns the head for this tenant's chain

        Returns:
            The latest Capsule or None if chain is empty
        """
        return await self.storage.get_latest(tenant_id=tenant_id)

    async def seal_and_store(
        self,
        capsule: Capsule,
        seal: Seal | None = None,
        tenant_id: str | None = None,
    ) -> Capsule:
        """
        Chain, seal, and store a Capsule in one call.

        Writers in one process take turns: a per-storage lock is held from
        reading the chain head through the store, so they never claim the
        same sequence. Writers in other processes are handled by optimistic
        retry: the UNIQUE constraint on the storage backend rejects a
        duplicate sequence and this method waits a short random time, then
        retries with the updated chain head, up to ``_MAX_CHAIN_RETRIES``
        times.

        Raises:
            ChainConflictError: If all retries are exhausted.
        """
        async with _chain_lock(self.storage):
            return await self._seal_and_store_locked(capsule, seal, tenant_id)

    async def _seal_and_store_locked(
        self,
        capsule: Capsule,
        seal: Seal | None,
        tenant_id: str | None,
    ) -> Capsule:
        from qp_capsule.seal import Seal as SealCls

        seal_instance = seal or SealCls()

        for attempt in range(_MAX_CHAIN_RETRIES):
            if attempt:
                await asyncio.sleep(random.uniform(0, _RETRY_JITTER_S * attempt))  # noqa: S311 - jitter, not security
            capsule = await self.add(capsule, tenant_id=tenant_id)
            capsule = seal_instance.seal(capsule)

            try:
                return await self.storage.store(capsule, tenant_id=tenant_id)
            except Exception as exc:
                if not _is_integrity_error(exc):
                    raise

                _log.warning(
                    "Chain sequence conflict (attempt %d/%d, seq=%d, tenant=%s), retrying",
                    attempt + 1,
                    _MAX_CHAIN_RETRIES,
                    capsule.sequence,
                    tenant_id,
                )
                capsule.hash = ""
                capsule.signature = ""
                capsule.signature_pq = ""
                capsule.signed_at = None
                capsule.signed_by = ""

        raise ChainConflictError(
            f"Failed to add Capsule to chain after {_MAX_CHAIN_RETRIES} retries "
            f"(concurrent writes for tenant={tenant_id!r})"
        )


def _is_integrity_error(exc: BaseException) -> bool:
    """Check if an exception is a database integrity/unique-constraint violation."""
    from qp_capsule.exceptions import StorageError

    name = type(exc).__name__
    if name in ("IntegrityError", "UniqueViolationError"):
        return True
    if isinstance(exc, StorageError) and exc.__cause__ is not None:
        return _is_integrity_error(exc.__cause__)
    return False
