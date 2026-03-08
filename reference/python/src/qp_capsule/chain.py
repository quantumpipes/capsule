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
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from qp_capsule.seal import compute_hash

if TYPE_CHECKING:
    from qp_capsule.capsule import Capsule
    from qp_capsule.protocol import CapsuleStorageProtocol
    from qp_capsule.seal import Seal


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
                computed = compute_hash(capsule.to_dict())
                if computed != capsule.hash:
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
        """Chain, seal, and store a capsule in one call."""
        from qp_capsule.seal import Seal as SealCls

        capsule = await self.add(capsule, tenant_id=tenant_id)
        seal_instance = seal or SealCls()
        capsule = seal_instance.seal(capsule)
        return await self.storage.store(capsule, tenant_id=tenant_id)
