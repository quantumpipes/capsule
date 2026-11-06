"""Exact raw reads bound evidence before parsing and keep writer lifecycle separate."""

import asyncio
import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import FrozenInstanceError
from unittest.mock import patch
from uuid import uuid4

import pytest
import pytest_asyncio

from qp_capsule import Capsule, CapsuleStorage, Seal, storage_read
from qp_capsule.records import (
    CapsuleRecordReader,
    RecordReadCode,
    RecordReadError,
    record_from_columns,
)


@contextmanager
def connected(db):
    connection = sqlite3.connect(db)
    try:
        with connection:
            yield connection
    finally:
        connection.close()


@pytest_asyncio.fixture
async def stored(tmp_path):
    db = tmp_path / "literal ?#% evidence.sqlite"
    capsule = Capsule()
    Seal(key_path=tmp_path / "keys" / "key", enable_pq=False).seal(capsule)
    storage = CapsuleStorage(db)
    await storage.store(capsule)
    await storage.close()
    return db, capsule


def change(db, column, value):
    # The column comes only from the fixed parameterized test census below.
    with connected(db) as connection:
        connection.execute(f'UPDATE capsules SET "{column}" = ?', (value,))


async def expect(code, awaitable):
    with pytest.raises(RecordReadError) as error:
        await awaitable
    assert error.value.code is code
    assert str(error.value) == code.value
    assert error.value.__cause__ is None


async def test_cold_raw_read_owns_exact_bytes_and_never_calls_legacy_initialization(stored):
    db, capsule = stored
    reader = CapsuleStorage(db)
    assert isinstance(reader, CapsuleRecordReader)
    with connected(db) as conn:
        original = conn.execute("SELECT data FROM capsules").fetchone()[0].encode()
    with (
        patch.object(reader, "_ensure_db", side_effect=AssertionError("provisioning")),
        patch.object(reader, "get", side_effect=AssertionError("legacy get")),
        patch.object(json, "loads", side_effect=AssertionError("premature parsing")),
    ):
        raw = await reader.read_record(capsule.id, tenant_id=None)
    assert reader._engine is None
    assert raw.capsule_id == capsule.id
    assert raw.content == original
    assert raw.hash == capsule.hash.encode()
    assert raw.signature == capsule.signature.encode()
    assert raw.signature_pq == b""
    with pytest.raises(FrozenInstanceError):
        raw.content = b"changed"
    change(db, "data", "later snapshot")
    assert raw.content == original


async def test_missing_database_and_parent_stay_absent(tmp_path):
    db = tmp_path / "absent" / "capsules.sqlite"
    await expect(
        RecordReadCode.UNAVAILABLE, CapsuleStorage(db).read_record(uuid4(), tenant_id=None)
    )
    assert not db.parent.exists()


async def test_missing_id_is_distinct_from_missing_schema(stored, tmp_path):
    db, _ = stored
    assert await CapsuleStorage(db).read_record(uuid4(), tenant_id=None) is None
    empty = tmp_path / "empty.sqlite"
    with connected(empty) as connection:
        connection.execute("PRAGMA user_version=3")
    before = empty.read_bytes()
    await expect(
        RecordReadCode.SCHEMA_UNSUPPORTED,
        CapsuleStorage(empty).read_record(uuid4(), tenant_id=None),
    )
    assert empty.read_bytes() == before


@pytest.mark.parametrize("identifier", ["", "abc", str(uuid4()), True, None])
async def test_requires_an_actual_full_uuid_before_io(tmp_path, identifier):
    await expect(
        RecordReadCode.INVALID_ID,
        CapsuleStorage(tmp_path / "absent").read_record(identifier, tenant_id=None),
    )
    assert not (tmp_path / "absent").exists()


@pytest.mark.parametrize("limit", [0, -1, True, 1.5, "10", 1024 * 1024 + 1])
async def test_invalid_limits_reject_before_io(tmp_path, limit):
    await expect(
        RecordReadCode.INVALID_LIMIT,
        CapsuleStorage(tmp_path / "absent").read_record(
            uuid4(), tenant_id=None, max_content_bytes=limit
        ),
    )


@pytest.mark.parametrize("scope", ["tenant-a", "", False])
async def test_sqlite_never_ignores_a_supplied_tenant(stored, scope):
    db, capsule = stored
    await expect(
        RecordReadCode.INVALID_SCOPE,
        CapsuleStorage(db).read_record(capsule.id, tenant_id=scope),
    )


@pytest.mark.parametrize(
    "column,limit",
    [
        ("data", 65536),
        ("hash", 64),
        ("signature", 128),
        ("signature_pq", 6618),
        ("signed_at", 64),
        ("signed_by", 256),
    ],
)
async def test_every_projected_field_rejects_oversize_instead_of_truncating(stored, column, limit):
    db, capsule = stored
    change(db, column, "x" * (limit + 1))
    await expect(
        RecordReadCode.TOO_LARGE, CapsuleStorage(db).read_record(capsule.id, tenant_id=None)
    )


async def test_byte_limits_count_unicode_and_embedded_nul(stored):
    db, capsule = stored
    data = "é\x00" * 10
    change(db, "data", data)
    reader = CapsuleStorage(db)
    raw = await reader.read_record(capsule.id, tenant_id=None, max_content_bytes=30)
    assert raw.content == data.encode()
    await expect(
        RecordReadCode.TOO_LARGE,
        reader.read_record(capsule.id, tenant_id=None, max_content_bytes=29),
    )


@pytest.mark.parametrize("column", ["data", "hash", "signature", "signature_pq", "signed_at"])
async def test_blob_substitution_is_not_coerced_to_text(stored, column):
    db, capsule = stored
    change(db, column, b"binary field")
    await expect(
        RecordReadCode.INVALID_RECORD, CapsuleStorage(db).read_record(capsule.id, tenant_id=None)
    )


async def test_large_native_row_is_rejected_with_finite_error(stored):
    db, capsule = stored
    change(db, "data", "PRIVATE_CANARY" * (1024 * 1024))
    await expect(
        RecordReadCode.TOO_LARGE, CapsuleStorage(db).read_record(capsule.id, tenant_id=None)
    )


async def test_null_optional_envelope_is_preserved_without_granting_validity(stored):
    db, capsule = stored
    with connected(db) as connection:
        connection.execute("UPDATE capsules SET signed_at = NULL, signed_by = NULL")
    raw = await CapsuleStorage(db).read_record(capsule.id, tenant_id=None)
    assert raw.signed_at is None and raw.signed_by is None
    assert raw.signature_pq == b""


async def test_raw_reader_preserves_duplicate_keys_and_signed_id_disagreement_for_consumer(stored):
    db, capsule = stored
    content = '{"id":"different","scope":"first","scope":"second"}'
    change(db, "data", content)
    raw = await CapsuleStorage(db).read_record(capsule.id, tenant_id=None)
    assert raw.content == content.encode()
    # The raw reader is not the parser, cryptographic verifier or authority gate.
    assert raw.capsule_id == capsule.id


@pytest.mark.parametrize(
    "ddl",
    [
        "CREATE VIEW capsules AS SELECT 'x' AS id",
        "CREATE TABLE capsules (id TEXT)",
        "CREATE TABLE capsules (id TEXT, other TEXT, PRIMARY KEY (id, other))",
    ],
)
async def test_view_or_noncanonical_primary_key_is_unsupported(tmp_path, ddl):
    db = tmp_path / "schema.sqlite"
    with connected(db) as conn:
        conn.execute(ddl)
    before = db.read_bytes()
    await expect(
        RecordReadCode.SCHEMA_UNSUPPORTED, CapsuleStorage(db).read_record(uuid4(), tenant_id=None)
    )
    assert db.read_bytes() == before


async def test_utf16_store_is_explicitly_unsupported(tmp_path):
    db = tmp_path / "utf16.sqlite"
    with connected(db) as conn:
        conn.execute("PRAGMA encoding='UTF-16'")
        conn.execute("CREATE TABLE capsules (id TEXT PRIMARY KEY)")
    await expect(
        RecordReadCode.UNSUPPORTED, CapsuleStorage(db).read_record(uuid4(), tenant_id=None)
    )


async def test_older_sqlite_does_not_fall_back_to_unbounded_get(stored):
    db, capsule = stored
    with patch.object(sqlite3, "sqlite_version_info", (3, 42, 0)):
        await expect(
            RecordReadCode.UNSUPPORTED, CapsuleStorage(db).read_record(capsule.id, tenant_id=None)
        )


async def test_wal_only_committed_record_is_visible(stored):
    db, capsule = stored
    with connected(db) as writer:
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("UPDATE capsules SET data = ?", ("committed in WAL",))
        writer.commit()
        assert db.with_name(db.name + "-wal").stat().st_size > 0
        raw = await CapsuleStorage(db).read_record(capsule.id, tenant_id=None)
        assert raw.content == b"committed in WAL"
        assert writer.execute("SELECT data FROM capsules").fetchone()[0] == "committed in WAL"


async def test_locked_store_returns_busy_with_finite_message(stored):
    db, capsule = stored
    with connected(db) as writer:
        writer.execute("PRAGMA journal_mode=DELETE")
        writer.execute("BEGIN EXCLUSIVE")
        try:
            await expect(
                RecordReadCode.BUSY, CapsuleStorage(db).read_record(capsule.id, tenant_id=None)
            )
        finally:
            writer.rollback()


@pytest.mark.parametrize("cancel", [False, True])
async def test_canceled_or_timed_out_reads_keep_admission_slots_until_workers_finish(
    stored, cancel
):
    db, capsule = stored
    started = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    lock = threading.Lock()
    counters = [0, 0]
    original = storage_read._read_sqlite

    def blocked(*args):
        with lock:
            counters[0] += 1
            if counters[0] == 4:
                started.set()
        release.wait(5)
        try:
            return original(*args)
        finally:
            with lock:
                counters[1] += 1
                if counters[1] == 4:
                    finished.set()

    with (
        patch.object(storage_read, "_read_sqlite", blocked),
        patch.object(storage_read, "_QUERY_SECONDS", 1.0 if cancel else 0.1),
    ):
        tasks = [
            asyncio.create_task(CapsuleStorage(db).read_record(capsule.id, tenant_id=None))
            for _ in range(4)
        ]
        try:
            assert await asyncio.wait_for(asyncio.to_thread(started.wait, 2), 3)
            if cancel:
                for task in tasks:
                    task.cancel()
            results = await asyncio.gather(*tasks, return_exceptions=True)
            assert all(
                isinstance(result, asyncio.CancelledError if cancel else RecordReadError)
                for result in results
            )
            if not cancel:
                assert all(result.code is RecordReadCode.DEADLINE for result in results)
            await expect(
                RecordReadCode.OVERLOADED,
                CapsuleStorage(db).read_record(capsule.id, tenant_id=None),
            )
        finally:
            release.set()
            assert await asyncio.wait_for(asyncio.to_thread(finished.wait, 2), 3)
            await asyncio.gather(*tasks, return_exceptions=True)
    assert await CapsuleStorage(db).read_record(capsule.id, tenant_id=None) is not None


@pytest.mark.parametrize(
    "error,code",
    [
        (sqlite3.SQLITE_INTERRUPT, RecordReadCode.DEADLINE),
        (sqlite3.SQLITE_LOCKED, RecordReadCode.BUSY),
        (sqlite3.SQLITE_BUSY | (2 << 8), RecordReadCode.BUSY),
        (sqlite3.SQLITE_TOOBIG, RecordReadCode.TOO_LARGE),
        (sqlite3.SQLITE_CORRUPT, RecordReadCode.UNAVAILABLE),
        (None, RecordReadCode.UNAVAILABLE),
    ],
)
async def test_native_failures_never_disclose_driver_payload(stored, error, code):
    db, capsule = stored
    exc = sqlite3.OperationalError("PRIVATE_SQL_AND_PATH")
    if error is not None:
        exc.sqlite_errorcode = error
    with patch.object(sqlite3, "connect", side_effect=exc):
        await expect(code, CapsuleStorage(db).read_record(capsule.id, tenant_id=None))


async def test_executor_submission_failure_releases_admission(stored):
    db, capsule = stored
    with patch.object(
        storage_read._READ_EXECUTOR, "submit", side_effect=RuntimeError("PRIVATE_EXECUTOR_STATE")
    ):
        await expect(
            RecordReadCode.UNAVAILABLE, CapsuleStorage(db).read_record(capsule.id, tenant_id=None)
        )
    assert await CapsuleStorage(db).read_record(capsule.id, tenant_id=None) is not None


async def test_canceling_queued_jobs_releases_capacity_before_executor_replacement(stored):
    db, capsule = stored
    release = threading.Event()
    started = threading.Event()
    executor = ThreadPoolExecutor(max_workers=1)

    def occupy():
        started.set()
        release.wait(5)

    blocker = executor.submit(occupy)
    assert await asyncio.wait_for(asyncio.to_thread(started.wait, 2), 3)
    submitted = []
    original_submit = executor.submit
    all_queued = asyncio.Event()

    def submit(*args, **kwargs):
        job = original_submit(*args, **kwargs)
        submitted.append(job)
        if len(submitted) == 4:
            all_queued.set()
        return job

    tasks = []
    try:
        with (
            patch.object(storage_read, "_READ_EXECUTOR", executor),
            patch.object(executor, "submit", submit),
        ):
            tasks = [
                asyncio.create_task(CapsuleStorage(db).read_record(capsule.id, tenant_id=None))
                for _ in range(4)
            ]
            await asyncio.wait_for(all_queued.wait(), 2)
            executor.shutdown(wait=False, cancel_futures=True)
            results = await asyncio.gather(*tasks, return_exceptions=True)
            assert all(isinstance(result, asyncio.CancelledError) for result in results)
            assert all(job.cancelled() for job in submitted)
        # The module's healthy executor can use all slots after the canceled queue.
        results = await asyncio.gather(
            *[CapsuleStorage(db).read_record(capsule.id, tenant_id=None) for _ in range(4)]
        )
        assert all(result is not None for result in results)
    finally:
        release.set()
        await asyncio.wrap_future(blocker)
        executor.shutdown(wait=True, cancel_futures=True)
        await asyncio.gather(*tasks, return_exceptions=True)


@pytest.mark.parametrize("column", [0, 1, 2, 3])
def test_snapshot_rejects_wrong_id_or_missing_required_column(column):
    identifier = uuid4()
    fields = [str(identifier).encode(), b"content", b"hash", b"signature", b"", None, None]
    fields[column] = b"different-id" if column == 0 else None
    with pytest.raises(RecordReadError) as error:
        record_from_columns(identifier, fields)
    assert error.value.code is RecordReadCode.INVALID_RECORD


@pytest.mark.parametrize("fault", ["multiple", "late", "identity"])
async def test_driver_snapshot_faults_fail_before_exposing_evidence(stored, fault):
    db, capsule = stored
    original_read = storage_read._read_sqlite
    original_connect = sqlite3.connect

    def read_with_fault(*args):
        cancelled = args[-1]

        class Snapshot:
            def __init__(self, rows):
                self.rows = rows

            def fetchall(self):
                if fault == "late":
                    cancelled.set()
                return self.rows

        class FaultConnection(sqlite3.Connection):
            def execute(self, sql, *parameters):
                cursor = super().execute(sql, *parameters)
                if sql != storage_read._READ_SQL:
                    return cursor
                rows = cursor.fetchall()
                if fault == "multiple":
                    rows *= 2
                if fault == "identity":
                    row = list(rows[0])
                    row[1] = b"wrong-id"
                    rows = [tuple(row)]
                return Snapshot(rows)

        def connect(*values, **keywords):
            return original_connect(*values, factory=FaultConnection, **keywords)

        with patch.object(sqlite3, "connect", connect):
            return original_read(*args)

    with patch.object(storage_read, "_read_sqlite", read_with_fault):
        await expect(
            RecordReadCode.DEADLINE if fault == "late" else RecordReadCode.INVALID_RECORD,
            CapsuleStorage(db).read_record(capsule.id, tenant_id=None),
        )
