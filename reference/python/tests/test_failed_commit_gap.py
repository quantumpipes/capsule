"""A failed commit must never leave a gap in the chain.

Measured on the AskQP desktop chain (2026-10-29, 2026-11-04): a capsule's COMMIT
failed with ``database is locked`` and the capsule was not recorded, but its
connection went back to the pool still inside that write. The next writer read the
chain head through it, saw the unsaved capsule, and linked to it. The chain then
held a successor whose ``previous_hash`` named a capsule nobody could produce.

These tests use the default pool, as the desktop does. ``NullPool`` closes every
connection and would hide the defect.
"""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from qp_capsule.capsule import Capsule, TriggerSection
from qp_capsule.chain import CapsuleChain
from qp_capsule.exceptions import ChainHeadMovedError
from qp_capsule.seal import Seal
from qp_capsule.storage import CapsuleStorage


def _capsule(note: str) -> Capsule:
    return Capsule(trigger=TriggerSection(type="system", source="test", request=note))


@pytest.fixture
async def pooled(tmp_path: Path):
    """Storage with the default pool and a short lock wait, so a lock fails fast.

    Under the rollback journal, the mode the desktop chain ran in when it lost
    capsules, and still the mode a file keeps when the switch to WAL is skipped.
    """
    storage = CapsuleStorage(db_path=tmp_path / "c.db", wal=False, connect_args={"timeout": 0.2})
    yield storage
    await storage.close()


def _rows(db: Path) -> list[tuple[int, str, str | None]]:
    with closing(sqlite3.connect(db)) as conn:
        return conn.execute(
            "SELECT sequence, hash, previous_hash FROM capsules ORDER BY sequence"
        ).fetchall()


async def test_a_commit_that_fails_on_a_lock_leaves_no_gap(
    pooled: CapsuleStorage, temp_seal: Seal
) -> None:
    chain = CapsuleChain(pooled)
    for i in range(3):
        await chain.seal_and_store(_capsule(f"before {i}"), seal=temp_seal)

    # A reader holding its lock is what makes the commit fail: under a rollback
    # journal a writer cannot commit past a reader.
    reader = sqlite3.connect(pooled.db_path, timeout=0.1, isolation_level=None)
    reader.execute("BEGIN")
    reader.execute("SELECT count(*) FROM capsules").fetchone()
    with pytest.raises(Exception, match="locked"):
        await chain.seal_and_store(_capsule("refused"), seal=temp_seal)
    reader.execute("COMMIT")
    reader.close()

    head = await pooled.get_latest()
    assert head is not None and head.sequence == 2, (
        "the refused capsule died with its connection, not visible as the head"
    )
    after = await chain.seal_and_store(_capsule("after"), seal=temp_seal)

    rows = _rows(pooled.db_path)
    assert [r[0] for r in rows] == [0, 1, 2, 3], "the refused capsule left no hole"
    assert after.sequence == 3
    assert after.previous_hash == rows[2][1]
    assert (await chain.verify(seal=temp_seal)).valid


async def test_store_linked_refuses_a_capsule_that_names_the_wrong_head(
    pooled: CapsuleStorage, temp_seal: Seal
) -> None:
    chain = CapsuleChain(pooled)
    await chain.seal_and_store(_capsule("one"), seal=temp_seal)
    stray = _capsule("stray")
    stray.sequence, stray.previous_hash = 1, "0" * 64
    temp_seal.seal(stray)

    with pytest.raises(ChainHeadMovedError):
        await pooled.store_linked(stray)

    assert [r[0] for r in _rows(pooled.db_path)] == [0], "nothing was written"


async def test_store_linked_refuses_a_first_capsule_that_names_a_previous(
    pooled: CapsuleStorage, temp_seal: Seal
) -> None:
    first = _capsule("first")
    first.sequence, first.previous_hash = 0, "0" * 64
    temp_seal.seal(first)
    with pytest.raises(ChainHeadMovedError):
        await pooled.store_linked(first)


async def test_plain_store_still_writes_a_chain_as_it_is(
    pooled: CapsuleStorage, temp_seal: Seal
) -> None:
    """Restores and verification tests write broken chains on purpose."""
    stray = _capsule("stray")
    stray.sequence, stray.previous_hash = 5, "0" * 64
    temp_seal.seal(stray)
    await pooled.store(stray)
    assert [r[0] for r in _rows(pooled.db_path)] == [5]


async def test_a_head_that_runs_ahead_of_the_store_is_retried(
    pooled: CapsuleStorage, temp_seal: Seal, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The shape of the defect without the lock: a head the store does not hold."""
    chain = CapsuleChain(pooled)
    for i in range(2):
        await chain.seal_and_store(_capsule(f"real {i}"), seal=temp_seal)

    phantom = _capsule("never stored")
    phantom.sequence, phantom.previous_hash = 2, _rows(pooled.db_path)[1][1]
    temp_seal.seal(phantom)
    real_latest = pooled.get_latest
    calls = 0

    async def latest_once_phantom(tenant_id: str | None = None) -> Capsule | None:
        nonlocal calls
        calls += 1
        return phantom if calls == 1 else await real_latest(tenant_id=tenant_id)

    monkeypatch.setattr(pooled, "get_latest", latest_once_phantom)
    stored = await chain.seal_and_store(_capsule("next"), seal=temp_seal)

    assert stored.sequence == 2, "retried on the real head"
    assert [r[0] for r in _rows(pooled.db_path)] == [0, 1, 2]
    assert (await chain.verify(seal=temp_seal)).valid


# --- WAL: a reader no longer costs a capsule --------------------------------------------


@pytest.fixture
async def wal_store(tmp_path: Path):
    storage = CapsuleStorage(db_path=tmp_path / "w.db", connect_args={"timeout": 0.2})
    yield storage
    await storage.close()


async def test_the_store_puts_its_file_in_wal_mode(
    wal_store: CapsuleStorage, temp_seal: Seal
) -> None:
    await CapsuleChain(wal_store).seal_and_store(_capsule("one"), seal=temp_seal)
    with closing(sqlite3.connect(wal_store.db_path)) as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


async def test_a_reader_mid_transaction_no_longer_blocks_a_commit(
    wal_store: CapsuleStorage, temp_seal: Seal
) -> None:
    """The 331 lost capsules: under the rollback journal this commit fails."""
    chain = CapsuleChain(wal_store)
    await chain.seal_and_store(_capsule("before"), seal=temp_seal)
    reader = sqlite3.connect(wal_store.db_path, timeout=0.1, isolation_level=None)
    reader.execute("BEGIN")
    reader.execute("SELECT count(*) FROM capsules").fetchone()
    try:
        stored = await chain.seal_and_store(_capsule("during a read"), seal=temp_seal)
    finally:
        reader.execute("COMMIT")
        reader.close()
    assert stored.sequence == 1
    assert [r[0] for r in _rows(wal_store.db_path)] == [0, 1]


def test_the_busy_timeout_defaults_longer_than_pysqlite(tmp_path: Path) -> None:
    from qp_capsule.storage import BUSY_TIMEOUT_S

    default = CapsuleStorage(db_path=tmp_path / "a.db")
    chosen = CapsuleStorage(db_path=tmp_path / "b.db", connect_args={"timeout": 1})
    assert BUSY_TIMEOUT_S > 5
    assert default._engine_kwargs["connect_args"]["timeout"] == BUSY_TIMEOUT_S
    assert chosen._engine_kwargs["connect_args"]["timeout"] == 1


class _Cursor:
    """A DB-API cursor whose PRAGMA answers or raises as told."""

    def __init__(self, mode: str | None = None, error: Exception | None = None) -> None:
        self.mode, self.error, self.closed = mode, error, False

    def execute(self, _sql: str) -> None:
        if self.error is not None:
            raise self.error

    def fetchone(self) -> tuple[str] | None:
        return (self.mode,) if self.mode is not None else None

    def close(self) -> None:
        self.closed = True


class _Conn:
    def __init__(self, cursor: _Cursor) -> None:
        self._cursor = cursor

    def cursor(self) -> _Cursor:
        return self._cursor


def test_a_file_that_stays_in_another_journal_mode_is_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from qp_capsule.storage import _use_wal

    cursor = _Cursor(mode="delete")
    with caplog.at_level("WARNING", logger="qp_capsule.storage"):
        _use_wal(_Conn(cursor), None)
    assert "stayed in delete journal mode" in caplog.text
    assert cursor.closed


def test_a_skipped_switch_to_wal_is_logged_and_not_raised(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from qp_capsule.storage import _use_wal

    cursor = _Cursor(error=sqlite3.OperationalError("database is locked"))
    with caplog.at_level("WARNING", logger="qp_capsule.storage"):
        _use_wal(_Conn(cursor), None)
    assert "could not switch to WAL yet: database is locked" in caplog.text
    assert cursor.closed
