# Copyright 2026 Quantum Pipes Technologies, LLC
# SPDX-License-Identifier: Apache-2.0

"""
Tests for hash chain concurrency protection (v1.5.0).

Validates:
    - UNIQUE constraint prevents duplicate sequence numbers
    - seal_and_store() retries on IntegrityError (optimistic concurrency)
    - ChainConflictError raised after max retries exhausted
    - _is_integrity_error() detects wrapped and unwrapped violations
    - Seal fields are properly reset between retry attempts
    - DDL event registered for PG global sequence index
    - Model constraints are correctly defined
    - CLI _get_version() returns correct version
    - Capsule identity preserved across retries
    - Warning emitted on conflict
"""

import logging
from unittest.mock import AsyncMock

import pytest

from qp_capsule.capsule import Capsule, TriggerSection
from qp_capsule.chain import (
    _MAX_CHAIN_RETRIES,
    CapsuleChain,
    _is_integrity_error,
)
from qp_capsule.exceptions import (
    CapsuleError,
    ChainConflictError,
    ChainError,
    StorageError,
)


def _make_capsule(request: str = "test") -> Capsule:
    return Capsule(trigger=TriggerSection(type="test", source="test", request=request))


# =============================================================================
# ChainConflictError
# =============================================================================


class TestChainConflictError:
    """ChainConflictError exception hierarchy and behavior."""

    def test_is_chain_error(self):
        """ChainConflictError is a subclass of ChainError."""
        assert issubclass(ChainConflictError, ChainError)

    def test_is_catchable_as_chain_error(self):
        """Code catching ChainError will also catch ChainConflictError."""
        with pytest.raises(ChainError):
            raise ChainConflictError("conflict")

    def test_message_preserved(self):
        """Error message is accessible."""
        err = ChainConflictError("seq=5 tenant=abc")
        assert "seq=5" in str(err)
        assert "tenant=abc" in str(err)


# =============================================================================
# _is_integrity_error
# =============================================================================


class TestIsIntegrityError:
    """Detection of database integrity violations across wrappers."""

    def test_raw_integrity_error(self):
        """Detects an exception named IntegrityError."""
        exc = type("IntegrityError", (Exception,), {})()
        assert _is_integrity_error(exc) is True

    def test_raw_unique_violation_error(self):
        """Detects asyncpg's UniqueViolationError."""
        exc = type("UniqueViolationError", (Exception,), {})()
        assert _is_integrity_error(exc) is True

    def test_wrapped_in_storage_error(self):
        """Detects IntegrityError wrapped in StorageError.__cause__."""
        cause = type("IntegrityError", (Exception,), {})()
        wrapper = StorageError("store failed")
        wrapper.__cause__ = cause
        assert _is_integrity_error(wrapper) is True

    def test_double_wrapped(self):
        """Detects IntegrityError two layers deep."""
        root = type("IntegrityError", (Exception,), {})()
        inner = StorageError("inner")
        inner.__cause__ = root
        outer = StorageError("outer")
        outer.__cause__ = inner
        assert _is_integrity_error(outer) is True

    def test_unrelated_error_rejected(self):
        """Non-integrity exceptions are not matched."""
        assert _is_integrity_error(ValueError("bad value")) is False
        assert _is_integrity_error(RuntimeError("timeout")) is False
        assert _is_integrity_error(StorageError("disk full")) is False

    def test_storage_error_without_cause(self):
        """StorageError with no __cause__ is not an integrity error."""
        assert _is_integrity_error(StorageError("generic")) is False


# =============================================================================
# seal_and_store() — Optimistic Retry
# =============================================================================


class TestSealAndStoreRetry:
    """seal_and_store() retries on sequence conflicts."""

    @pytest.mark.asyncio
    async def test_succeeds_on_first_attempt(self, temp_storage, temp_seal, temp_chain):
        """Happy path: no conflict, stores immediately."""
        capsule = _make_capsule("first-try")
        stored = await temp_chain.seal_and_store(capsule, seal=temp_seal)

        assert stored.is_sealed()
        assert stored.sequence == 0

    @pytest.mark.asyncio
    async def test_succeeds_after_one_retry(self, temp_seal):
        """Simulates one conflict then success on second attempt."""
        integrity_err = type("IntegrityError", (Exception,), {})()

        mock_storage = AsyncMock()
        mock_storage.get_latest = AsyncMock(return_value=None)
        mock_storage.store = AsyncMock(side_effect=[integrity_err, _make_capsule()])

        chain = CapsuleChain(mock_storage)
        capsule = _make_capsule("retry-once")

        await chain.seal_and_store(capsule, seal=temp_seal)

        assert mock_storage.store.call_count == 2
        assert mock_storage.get_latest.call_count == 2

    @pytest.mark.asyncio
    async def test_raises_after_max_retries(self, temp_seal):
        """Three consecutive conflicts exhaust retries."""
        integrity_err = type("IntegrityError", (Exception,), {})()

        mock_storage = AsyncMock()
        mock_storage.get_latest = AsyncMock(return_value=None)
        mock_storage.store = AsyncMock(side_effect=integrity_err)

        chain = CapsuleChain(mock_storage)
        capsule = _make_capsule("always-conflict")

        with pytest.raises(ChainConflictError, match="3 retries"):
            await chain.seal_and_store(capsule, seal=temp_seal)

        assert mock_storage.store.call_count == 3

    @pytest.mark.asyncio
    async def test_conflict_error_includes_tenant(self, temp_seal):
        """ChainConflictError message includes the tenant_id."""
        integrity_err = type("IntegrityError", (Exception,), {})()

        mock_storage = AsyncMock()
        mock_storage.get_latest = AsyncMock(return_value=None)
        mock_storage.store = AsyncMock(side_effect=integrity_err)

        chain = CapsuleChain(mock_storage)

        with pytest.raises(ChainConflictError, match="tenant='org-42'"):
            await chain.seal_and_store(_make_capsule(), seal=temp_seal, tenant_id="org-42")

    @pytest.mark.asyncio
    async def test_non_integrity_error_not_retried(self, temp_seal):
        """Non-integrity exceptions propagate immediately without retry."""
        mock_storage = AsyncMock()
        mock_storage.get_latest = AsyncMock(return_value=None)
        mock_storage.store = AsyncMock(side_effect=RuntimeError("disk on fire"))

        chain = CapsuleChain(mock_storage)

        with pytest.raises(RuntimeError, match="disk on fire"):
            await chain.seal_and_store(_make_capsule(), seal=temp_seal)

        assert mock_storage.store.call_count == 1

    @pytest.mark.asyncio
    async def test_wrapped_integrity_error_retried(self, temp_seal):
        """IntegrityError wrapped in StorageError triggers retry."""
        cause = type("IntegrityError", (Exception,), {})()
        wrapped = StorageError("store failed")
        wrapped.__cause__ = cause

        mock_storage = AsyncMock()
        mock_storage.get_latest = AsyncMock(return_value=None)
        mock_storage.store = AsyncMock(side_effect=[wrapped, _make_capsule()])

        chain = CapsuleChain(mock_storage)
        await chain.seal_and_store(_make_capsule(), seal=temp_seal)

        assert mock_storage.store.call_count == 2

    @pytest.mark.asyncio
    async def test_seal_fields_reset_between_retries(self, temp_seal):
        """Hash, signature, and metadata are cleared before each retry."""
        integrity_err = type("IntegrityError", (Exception,), {})()
        stored_capsules = []

        async def capture_store(capsule, **kwargs):
            stored_capsules.append(capsule)
            if len(stored_capsules) < 2:
                raise integrity_err
            return capsule

        mock_storage = AsyncMock()
        mock_storage.get_latest = AsyncMock(return_value=None)
        mock_storage.store = AsyncMock(side_effect=capture_store)

        chain = CapsuleChain(mock_storage)
        capsule = _make_capsule("check-reset")

        await chain.seal_and_store(capsule, seal=temp_seal)

        first = stored_capsules[0]
        second = stored_capsules[1]
        assert first.is_sealed()
        assert second.is_sealed()
        assert first.hash != "" and second.hash != ""


# =============================================================================
# UNIQUE Constraint — SQLite
# =============================================================================


class TestSQLiteUniqueConstraint:
    """UNIQUE(sequence) on SQLite CapsuleModel prevents duplicate sequences."""

    @pytest.mark.asyncio
    async def test_duplicate_sequence_rejected(self, temp_storage, temp_seal):
        """Two capsules with the same sequence cause IntegrityError."""
        from sqlalchemy.exc import IntegrityError

        c1 = _make_capsule("first")
        c1.sequence = 0
        c1.previous_hash = None
        temp_seal.seal(c1)
        await temp_storage.store(c1)

        c2 = _make_capsule("second")
        c2.sequence = 0
        c2.previous_hash = None
        temp_seal.seal(c2)

        with pytest.raises(IntegrityError):
            await temp_storage.store(c2)

    @pytest.mark.asyncio
    async def test_different_sequences_allowed(self, temp_storage, temp_seal):
        """Distinct sequence numbers store without conflict."""
        for i in range(5):
            c = _make_capsule(f"capsule-{i}")
            c.sequence = i
            c.previous_hash = None
            temp_seal.seal(c)
            await temp_storage.store(c)

        assert await temp_storage.count() == 5


# =============================================================================
# seal_and_store() — Integration with Real Storage
# =============================================================================


class TestSealAndStoreIntegration:
    """End-to-end seal_and_store with real SQLite storage."""

    @pytest.mark.asyncio
    async def test_builds_valid_chain(self, temp_storage, temp_seal, temp_chain):
        """Multiple seal_and_store calls produce a verifiable chain."""
        for i in range(5):
            await temp_chain.seal_and_store(_make_capsule(f"cap-{i}"), seal=temp_seal)

        result = await temp_chain.verify()
        assert result.valid is True
        assert result.capsules_verified == 5

    @pytest.mark.asyncio
    async def test_chain_verifies_with_content(self, temp_storage, temp_seal, temp_chain):
        """Chain built with seal_and_store passes cryptographic verification."""
        for i in range(3):
            await temp_chain.seal_and_store(_make_capsule(f"cap-{i}"), seal=temp_seal)

        result = await temp_chain.verify(verify_content=True)
        assert result.valid is True

    @pytest.mark.asyncio
    async def test_chain_verifies_signatures(self, temp_storage, temp_seal, temp_chain):
        """Chain built with seal_and_store passes signature verification."""
        for i in range(3):
            await temp_chain.seal_and_store(_make_capsule(f"cap-{i}"), seal=temp_seal)

        result = await temp_chain.verify(seal=temp_seal)
        assert result.valid is True

    @pytest.mark.asyncio
    async def test_sequences_are_consecutive(self, temp_storage, temp_seal, temp_chain):
        """seal_and_store assigns consecutive sequence numbers."""
        capsules = []
        for i in range(5):
            c = await temp_chain.seal_and_store(_make_capsule(f"cap-{i}"), seal=temp_seal)
            capsules.append(c)

        assert [c.sequence for c in capsules] == [0, 1, 2, 3, 4]

    @pytest.mark.asyncio
    async def test_previous_hash_links_chain(self, temp_storage, temp_seal, temp_chain):
        """Each capsule's previous_hash matches the prior capsule's hash."""
        capsules = []
        for i in range(3):
            c = await temp_chain.seal_and_store(_make_capsule(f"cap-{i}"), seal=temp_seal)
            capsules.append(c)

        assert capsules[0].previous_hash is None
        assert capsules[1].previous_hash == capsules[0].hash
        assert capsules[2].previous_hash == capsules[1].hash

    @pytest.mark.asyncio
    async def test_seal_and_store_without_explicit_seal(self, temp_storage, temp_chain):
        """seal_and_store creates a default Seal if none provided."""
        stored = await temp_chain.seal_and_store(_make_capsule("auto-seal"))
        assert stored.is_sealed()
        assert stored.sequence == 0


# =============================================================================
# Model Constraints
# =============================================================================


class TestModelConstraints:
    """Database models have correct UNIQUE constraints."""

    def test_sqlite_model_has_sequence_constraint(self):
        """CapsuleModel has UNIQUE on sequence."""
        from qp_capsule.storage import CapsuleModel

        constraint_names = {
            c.name for c in CapsuleModel.__table__.constraints
            if hasattr(c, "columns") and "sequence" in {col.name for col in c.columns}
        }
        assert "uq_capsule_sequence" in constraint_names

    def test_pg_model_has_tenant_sequence_constraint(self):
        """CapsuleModelPG has UNIQUE on (tenant_id, sequence)."""
        from qp_capsule.storage_pg import CapsuleModelPG

        constraint_names = {
            c.name for c in CapsuleModelPG.__table__.constraints
            if hasattr(c, "columns")
        }
        assert "uq_capsule_tenant_sequence" in constraint_names

    def test_pg_global_ddl_event_registered(self):
        """DDL event for global sequence index is attached to CapsuleModelPG."""
        from qp_capsule.storage_pg import CapsuleModelPG

        dispatch = CapsuleModelPG.__table__.dispatch
        listeners = list(dispatch.after_create)
        assert len(listeners) > 0, "after_create DDL event must be registered on CapsuleModelPG"


# =============================================================================
# Retry Invariants
# =============================================================================


class TestRetryInvariants:
    """Properties that must hold across all retry scenarios."""

    def test_max_retries_is_three(self):
        """The retry constant is exactly 3."""
        assert _MAX_CHAIN_RETRIES == 3

    @pytest.mark.asyncio
    async def test_capsule_id_preserved_across_retries(self, temp_seal):
        """The same capsule.id is stored after a retry, not a new capsule."""
        integrity_err = type("IntegrityError", (Exception,), {})()
        stored_ids = []

        async def capture_store(capsule, **kwargs):
            stored_ids.append(str(capsule.id))
            if len(stored_ids) < 2:
                raise integrity_err
            return capsule

        mock_storage = AsyncMock()
        mock_storage.get_latest = AsyncMock(return_value=None)
        mock_storage.store = AsyncMock(side_effect=capture_store)

        chain = CapsuleChain(mock_storage)
        capsule = _make_capsule("id-check")
        original_id = str(capsule.id)

        await chain.seal_and_store(capsule, seal=temp_seal)

        assert stored_ids[0] == original_id
        assert stored_ids[1] == original_id

    @pytest.mark.asyncio
    async def test_warning_emitted_on_conflict(self, temp_seal, caplog):
        """A WARNING log is emitted on each retry."""
        integrity_err = type("IntegrityError", (Exception,), {})()

        mock_storage = AsyncMock()
        mock_storage.get_latest = AsyncMock(return_value=None)
        mock_storage.store = AsyncMock(side_effect=[integrity_err, _make_capsule()])

        chain = CapsuleChain(mock_storage)

        with caplog.at_level(logging.WARNING, logger="qp_capsule.chain"):
            await chain.seal_and_store(_make_capsule(), seal=temp_seal)

        assert any("sequence conflict" in r.message for r in caplog.records)

    @pytest.mark.asyncio
    async def test_retry_re_reads_chain_head(self, temp_seal):
        """Each retry calls get_latest again to get the updated head."""
        integrity_err = type("IntegrityError", (Exception,), {})()

        head_after_conflict = _make_capsule("already-stored")
        head_after_conflict.sequence = 0
        head_after_conflict.hash = "a" * 64

        mock_storage = AsyncMock()
        mock_storage.get_latest = AsyncMock(side_effect=[None, head_after_conflict])
        mock_storage.store = AsyncMock(side_effect=[integrity_err, _make_capsule()])

        chain = CapsuleChain(mock_storage)
        capsule = _make_capsule("retry-reread")

        await chain.seal_and_store(capsule, seal=temp_seal)

        assert mock_storage.get_latest.call_count == 2
        assert capsule.sequence == 1
        assert capsule.previous_hash == "a" * 64


# =============================================================================
# Exception Hierarchy
# =============================================================================


class TestExceptionHierarchy:
    """Full exception hierarchy for capsule errors."""

    def test_chain_conflict_inherits_capsule_error(self):
        """ChainConflictError is catchable as CapsuleError."""
        assert issubclass(ChainConflictError, CapsuleError)

    def test_chain_conflict_inherits_chain_error(self):
        """ChainConflictError is catchable as ChainError."""
        assert issubclass(ChainConflictError, ChainError)

    def test_chain_conflict_is_not_storage_error(self):
        """ChainConflictError is distinct from StorageError."""
        assert not issubclass(ChainConflictError, StorageError)


# =============================================================================
# CLI Version Helper
# =============================================================================


class TestCLIVersionHelper:
    """_get_version() returns the package version."""

    def test_returns_version_string(self):
        from qp_capsule.cli import _get_version

        version = _get_version()
        assert version == "1.5.2"

    def test_matches_package_version(self):
        import qp_capsule
        from qp_capsule.cli import _get_version

        assert _get_version() == qp_capsule.__version__
