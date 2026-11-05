"""Two stores opening a brand-new file at once both start.

Found by the AskQP core end-to-end tests on 2026-11-05: ``create_all`` checks for the
table, then creates it. Two stores on a new file both saw no table, both ran CREATE,
and the loser raised ``table capsules already exists``. Each test below pins one
branch of the retry that replaced that error.
"""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.exc import OperationalError

from qp_capsule import storage as storage_module
from qp_capsule.capsule import Capsule, TriggerSection
from qp_capsule.chain import CapsuleChain
from qp_capsule.storage import SCHEMA_ATTEMPTS, CapsuleStorage


def _raced(message: str = "table capsules already exists") -> OperationalError:
    return OperationalError("CREATE TABLE capsules", {}, sqlite3.OperationalError(message))


def _create_all_that_fails(
    monkeypatch: pytest.MonkeyPatch, failures: int, message: str
) -> list[int]:
    """Make the first ``failures`` schema creations raise, as a lost race does."""
    calls: list[int] = []
    real = storage_module.Base.metadata.create_all

    def create_all(bind: Any, **kwargs: Any) -> None:
        calls.append(1)
        if len(calls) <= failures:
            raise _raced(message)
        real(bind, **kwargs)

    monkeypatch.setattr(storage_module.Base.metadata, "create_all", create_all)
    return calls


async def test_a_store_that_loses_the_create_race_retries_and_starts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED PROOF: without the retry, this raises ``table capsules already exists``."""
    calls = _create_all_that_fails(monkeypatch, 1, "table capsules already exists")
    store = CapsuleStorage(db_path=tmp_path / "new.db")
    try:
        assert await store.count() == 0
        assert len(calls) == 2
    finally:
        await store.close()


async def test_a_race_on_an_index_is_retried_too(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _create_all_that_fails(monkeypatch, 1, "index ix_capsules_sequence already exists")
    store = CapsuleStorage(db_path=tmp_path / "new.db")
    try:
        assert await store.count() == 0
        assert len(calls) == 2
    finally:
        await store.close()


async def test_any_other_schema_error_still_raises_at_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _create_all_that_fails(monkeypatch, 1, "disk I/O error")
    store = CapsuleStorage(db_path=tmp_path / "new.db")
    with pytest.raises(OperationalError, match="disk I/O error"):
        await store.count()
    assert len(calls) == 1
    await store.close()


async def test_a_race_that_never_settles_raises_after_the_last_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _create_all_that_fails(monkeypatch, SCHEMA_ATTEMPTS, "table capsules already exists")
    store = CapsuleStorage(db_path=tmp_path / "new.db")
    with pytest.raises(OperationalError, match="already exists"):
        await store.count()
    assert len(calls) == SCHEMA_ATTEMPTS
    await store.close()


async def test_four_stores_on_a_brand_new_file_all_write_one_chain(tmp_path: Path) -> None:
    """Smoke check on the unpatched path: four stores create one new file and write.

    The real race fires only now and then in a run this short, so this passes with or
    without the retry; the patched tests above are the proof.
    """
    db = tmp_path / "first-launch.db"
    stores = [CapsuleStorage(db_path=db) for _ in range(4)]
    try:

        async def write(store: CapsuleStorage, who: int) -> None:
            capsule = Capsule(trigger=TriggerSection(type="t", source="t", request=f"w{who}"))
            await CapsuleChain(store).seal_and_store(capsule)

        await asyncio.gather(*(write(store, i) for i, store in enumerate(stores)))
        chain = await stores[0].get_all_ordered()
        assert sorted(int(c.sequence) for c in chain) == [0, 1, 2, 3]
    finally:
        for store in stores:
            await store.close()
