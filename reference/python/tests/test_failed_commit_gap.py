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
    """Storage with the default pool and a short lock wait, so a lock fails fast."""
    storage = CapsuleStorage(db_path=tmp_path / "c.db", connect_args={"timeout": 0.2})
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
