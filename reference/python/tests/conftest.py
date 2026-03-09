# Copyright 2026 Quantum Pipes Technologies, LLC
# SPDX-License-Identifier: Apache-2.0

"""
Shared test fixtures for the Capsule test suite.

Provides temporary storage and seal instances that are isolated per test.
"""

import asyncio
import warnings
from pathlib import Path

import pytest
from sqlalchemy.pool import NullPool

from qp_capsule.chain import CapsuleChain
from qp_capsule.seal import Seal
from qp_capsule.storage import CapsuleStorage


@pytest.fixture(autouse=True)
def _close_stale_event_loops():
    """Close orphaned event loops between tests.

    pytest-asyncio's per-test loops can survive teardown in the global event
    loop policy.  When a later sync test calls ``asyncio.run()``, the stale
    loop is dereferenced without closing, and its self-pipe sockets trigger
    ``ResourceWarning`` on GC.  Closing here keeps ``filterwarnings=error``
    strict.
    """
    yield
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            return
    if not loop.is_running() and not loop.is_closed():
        loop.close()


@pytest.fixture
async def temp_storage(tmp_path: Path):
    """Create temporary SQLite storage for testing. Closes on teardown."""
    db_path = tmp_path / "test_capsules.db"
    storage = CapsuleStorage(db_path=db_path, poolclass=NullPool)
    yield storage
    await storage.close()


@pytest.fixture
def temp_seal(tmp_path: Path) -> Seal:
    """Create temporary seal with isolated test key."""
    key_path = tmp_path / "test_key"
    return Seal(key_path=key_path)


@pytest.fixture
async def temp_chain(temp_storage: CapsuleStorage):
    """Create a chain with temporary storage."""
    yield CapsuleChain(storage=temp_storage)
