# Copyright 2026 Quantum Pipes Technologies, LLC
# SPDX-License-Identifier: Apache-2.0

"""Exact SQLite evidence reads without provisioning or application writes.

SQLite may create or update WAL coordination files. This module does not promise
filesystem immutability, source-path authenticity, rollback detection or a hard
OS scheduling deadline. The configured database location and schema owner are
trusted. Result bytes, active work and SQLite query/lock waits are bounded here.
"""

from __future__ import annotations

import asyncio
import sqlite3
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from uuid import UUID

from qp_capsule.records import (
    RECORD_FIELDS,
    RawCapsuleRecord,
    RecordReadCode,
    RecordReadError,
    record_from_columns,
    validate_read,
)

_READ_SLOTS = threading.BoundedSemaphore(4)
_READ_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="capsule-evidence")
_QUERY_SECONDS = 2.0
_LOCK_SECONDS = 0.2

# All projected identifiers come from the fixed internal tuple. SQL returns a
# type tag and either a bounded BLOB or NULL, never a silently truncated record.
_PROJECTION = ", ".join(
    f"typeof({name}), CASE WHEN typeof({name}) = 'text' "
    f"AND octet_length({name}) <= :{name}_limit THEN CAST({name} AS BLOB) END"
    for name, _, _ in RECORD_FIELDS
)
# B608: the projection contains only fixed internal column names; all caller
# values remain bound parameters, including the UUID and every size ceiling.
_READ_SQL = f"SELECT {_PROJECTION} FROM capsules WHERE id = :capsule_id LIMIT 2"  # nosec B608


def _read_sqlite(
    db_path: Path,
    capsule_id: UUID,
    max_content_bytes: int,
    deadline: float,
    cancelled: threading.Event,
) -> RawCapsuleRecord | None:
    connection: sqlite3.Connection | None = None
    try:
        if cancelled.is_set() or time.monotonic() >= deadline:
            raise RecordReadError(RecordReadCode.DEADLINE)
        # as_uri escapes literal ?, # and % in paths. mode=ro refuses to create
        # an absent database. immutable=1 would hide live WAL state.
        connection = sqlite3.connect(
            db_path.absolute().as_uri() + "?mode=ro", uri=True, timeout=_LOCK_SECONDS
        )
        connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, max_content_bytes + 16 * 1024)
        connection.setlimit(sqlite3.SQLITE_LIMIT_COLUMN, 32)
        connection.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 16 * 1024)
        connection.set_progress_handler(
            lambda: int(cancelled.is_set() or time.monotonic() >= deadline), 100
        )
        connection.execute("PRAGMA query_only = ON")
        connection.execute("BEGIN")
        if connection.execute("PRAGMA encoding").fetchone() != ("UTF-8",):
            raise RecordReadError(RecordReadCode.UNSUPPORTED)
        # A view or virtual table is not the canonical ordinary capsule table.
        table = connection.execute(
            "SELECT type, rootpage > 0 FROM sqlite_schema WHERE name = 'capsules' LIMIT 2"
        ).fetchall()
        if table != [("table", 1)]:
            raise RecordReadError(RecordReadCode.SCHEMA_UNSUPPORTED)
        keys = connection.execute(
            "SELECT name FROM pragma_table_info('capsules') WHERE pk > 0 ORDER BY pk"
        ).fetchall()
        if keys != [("id",)]:
            raise RecordReadError(RecordReadCode.SCHEMA_UNSUPPORTED)

        params: dict[str, int | str] = {"capsule_id": str(capsule_id)}
        params.update(
            {
                f"{name}_limit": max_content_bytes if name == "data" else limit
                for name, limit, _ in RECORD_FIELDS
            }
        )
        rows = connection.execute(_READ_SQL, params).fetchall()
        if cancelled.is_set() or time.monotonic() >= deadline:
            raise RecordReadError(RecordReadCode.DEADLINE)
        if not rows:
            return None
        if len(rows) != 1:
            raise RecordReadError(RecordReadCode.INVALID_RECORD)
        values: list[bytes | None] = []
        for index, (_, _, nullable) in enumerate(RECORD_FIELDS):
            kind, value = rows[0][index * 2 : index * 2 + 2]
            if kind == "null" and nullable:
                values.append(None)
            elif kind != "text":
                raise RecordReadError(RecordReadCode.INVALID_RECORD)
            elif value is None:
                raise RecordReadError(RecordReadCode.TOO_LARGE)
            else:
                values.append(value)
        return record_from_columns(capsule_id, tuple(values))
    except (sqlite3.Error, OSError, ValueError) as exc:
        code = getattr(exc, "sqlite_errorcode", None)
        code = code & 0xFF if isinstance(code, int) else None
        if cancelled.is_set() or time.monotonic() >= deadline or code == sqlite3.SQLITE_INTERRUPT:
            reason = RecordReadCode.DEADLINE
        elif code in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
            reason = RecordReadCode.BUSY
        elif code == sqlite3.SQLITE_TOOBIG:
            reason = RecordReadCode.TOO_LARGE
        else:
            reason = RecordReadCode.UNAVAILABLE
        raise RecordReadError(reason) from None
    finally:
        if connection is not None:
            connection.close()


def _release_slot(_job: Future[RawCapsuleRecord | None]) -> None:
    """Release after actual cleanup or confirmed cancellation before a job starts."""
    _READ_SLOTS.release()


def _observe_completion(future: asyncio.Future[RawCapsuleRecord | None]) -> None:
    """Consume a late finite exception after its awaiting caller was canceled."""
    if not future.cancelled():
        future.exception()


async def read_sqlite_record(
    db_path: Path,
    capsule_id: UUID,
    *,
    tenant_id: str | None,
    max_content_bytes: int,
) -> RawCapsuleRecord | None:
    """Run one bounded, exact read outside the event loop and any writer transaction.

    Args:
        db_path: Trusted host-configured path to the existing canonical SQLite store.
        capsule_id: Full UUID to retrieve, with no prefix or string coercion.
        tenant_id: Must be None; SQLite has no tenant column. Check signed scope separately.
        max_content_bytes: Ceiling applied before Python receives content bytes.
    Returns:
        An immutable raw snapshot, or None for an absent ID in an available store.
    Raises:
        RecordReadError: Invalid inputs, unsupported runtime, overload or read failure.
        asyncio.CancelledError: Caller cancellation; the active slot stays held until cleanup.
    """
    validate_read(capsule_id, max_content_bytes)
    if tenant_id is not None:
        raise RecordReadError(RecordReadCode.INVALID_SCOPE)
    if sqlite3.sqlite_version_info < (3, 43, 0):
        raise RecordReadError(RecordReadCode.UNSUPPORTED)
    if not _READ_SLOTS.acquire(blocking=False):
        raise RecordReadError(RecordReadCode.OVERLOADED)
    cancelled = threading.Event()
    try:
        job = _READ_EXECUTOR.submit(
            _read_sqlite,
            db_path,
            capsule_id,
            max_content_bytes,
            time.monotonic() + _QUERY_SECONDS,
            cancelled,
        )
    except RuntimeError:
        _READ_SLOTS.release()
        raise RecordReadError(RecordReadCode.UNAVAILABLE) from None
    # A concurrent Future completes only after the worker finishes, or after a
    # queued job is actually canceled before starting. An asyncio waiter's canceled
    # state alone cannot distinguish those cases and must not free admission.
    job.add_done_callback(_release_slot)
    future = asyncio.wrap_future(job)
    future.add_done_callback(_observe_completion)
    try:
        async with asyncio.timeout(_QUERY_SECONDS):
            return await asyncio.shield(future)
    except TimeoutError:
        cancelled.set()
        raise RecordReadError(RecordReadCode.DEADLINE) from None
    except asyncio.CancelledError:
        cancelled.set()
        raise
