# Copyright 2026 Quantum Pipes Technologies, LLC
# SPDX-License-Identifier: Apache-2.0

"""
Tests for the high-level audit API (Capsules, @audit, current).

These tests verify that the convenience layer works correctly without
modifying any existing primitives. The decorator must:
    - Never block the user's function
    - Never change the return value or exception behavior
    - Create valid, sealed Capsules on success and failure
    - Support context-variable enrichment via current()
"""

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

from qp_capsule import CapsuleError, CapsuleStorage, CapsuleType, Seal
from qp_capsule.audit import Capsules
from qp_capsule.chain import CapsuleChain
from qp_capsule.protocol import CapsuleStorageProtocol

# ---------------------------------------------------------------------------
# Capsules init
# ---------------------------------------------------------------------------


class TestCapsulesInit:
    async def test_capsules_init_sqlite(self, tmp_path: Path) -> None:
        db_path = tmp_path / "audit.db"
        capsules = Capsules(str(db_path))
        assert isinstance(capsules.storage, CapsuleStorage)
        assert isinstance(capsules.chain, CapsuleChain)
        assert isinstance(capsules.seal, Seal)
        await capsules.close()

    async def test_capsules_init_default(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("QUANTUMPIPES_DATA_DIR", str(tmp_path))
        capsules = Capsules()
        assert isinstance(capsules.storage, CapsuleStorage)
        await capsules.close()

    async def test_capsules_init_custom_storage(self) -> None:
        mock_storage = AsyncMock(spec=CapsuleStorageProtocol)
        capsules = Capsules(storage=mock_storage)
        assert capsules.storage is mock_storage


# ---------------------------------------------------------------------------
# @audit decorator — async happy path
# ---------------------------------------------------------------------------


class TestAuditDecoratorSuccess:
    async def test_audit_decorator_success(self, tmp_path: Path) -> None:
        db = tmp_path / "test.db"
        capsules = Capsules(str(db))

        @capsules.audit(type="agent")
        async def my_task(prompt: str) -> dict[str, str]:
            return {"response": "hello"}

        result = await my_task("test prompt")
        assert result == {"response": "hello"}

        stored = await capsules.storage.list()
        assert len(stored) == 1
        cap = stored[0]
        assert cap.type == CapsuleType.AGENT
        assert cap.outcome.status == "success"
        assert cap.is_sealed()
        assert cap.trigger.request == "test prompt"
        await capsules.close()

    async def test_audit_preserves_return_value(self, tmp_path: Path) -> None:
        capsules = Capsules(str(tmp_path / "test.db"))

        @capsules.audit(type="tool")
        async def get_data() -> list[int]:
            return [1, 2, 3]

        result = await get_data()
        assert result == [1, 2, 3]
        await capsules.close()


# ---------------------------------------------------------------------------
# @audit decorator — failure path
# ---------------------------------------------------------------------------


class TestAuditDecoratorFailure:
    async def test_audit_decorator_failure(self, tmp_path: Path) -> None:
        capsules = Capsules(str(tmp_path / "test.db"))

        @capsules.audit(type="agent")
        async def failing_task(prompt: str) -> str:
            raise ValueError("something broke")

        with pytest.raises(ValueError, match="something broke"):
            await failing_task("test")

        stored = await capsules.storage.list()
        assert len(stored) == 1
        cap = stored[0]
        assert cap.outcome.status == "failure"
        assert cap.outcome.error == "something broke"
        assert cap.is_sealed()
        await capsules.close()


# ---------------------------------------------------------------------------
# swallow_errors behavior
# ---------------------------------------------------------------------------


class TestSwallowErrors:
    async def test_audit_decorator_never_blocks(self, tmp_path: Path) -> None:
        """Capsule seal failure must never affect the decorated function."""
        mock_storage = AsyncMock(spec=CapsuleStorageProtocol)
        mock_storage.get_latest = AsyncMock(return_value=None)
        mock_storage.store = AsyncMock(side_effect=RuntimeError("storage exploded"))
        mock_storage.close = AsyncMock()

        capsules = Capsules(storage=mock_storage)

        @capsules.audit(type="agent")
        async def my_task(prompt: str) -> str:
            return "still works"

        result = await my_task("test")
        assert result == "still works"
        await capsules.close()

    async def test_audit_decorator_propagates(self, tmp_path: Path) -> None:
        """When swallow_errors=False, capsule errors propagate."""
        mock_storage = AsyncMock(spec=CapsuleStorageProtocol)
        mock_storage.get_latest = AsyncMock(return_value=None)
        mock_storage.store = AsyncMock(side_effect=RuntimeError("storage exploded"))
        mock_storage.close = AsyncMock()

        capsules = Capsules(storage=mock_storage)

        @capsules.audit(type="agent", swallow_errors=False)
        async def my_task(prompt: str) -> str:
            return "result"

        with pytest.raises(RuntimeError, match="storage exploded"):
            await my_task("test")
        await capsules.close()


# ---------------------------------------------------------------------------
# Tenant extraction
# ---------------------------------------------------------------------------


class TestTenantExtraction:
    async def test_audit_tenant_from(self, tmp_path: Path) -> None:
        capsules = Capsules(str(tmp_path / "test.db"))

        @capsules.audit(type="agent", tenant_from="site_id")
        async def my_task(prompt: str, *, site_id: str) -> str:
            return "done"

        await my_task("hello", site_id="tenant-abc")

        stored = await capsules.storage.list(tenant_id="tenant-abc")
        assert len(stored) == 1
        await capsules.close()

    async def test_audit_tenant_static(self, tmp_path: Path) -> None:
        capsules = Capsules(str(tmp_path / "test.db"))

        @capsules.audit(type="agent", tenant_id="static-tenant")
        async def my_task(prompt: str) -> str:
            return "done"

        await my_task("hello")

        stored = await capsules.storage.list(tenant_id="static-tenant")
        assert len(stored) == 1
        await capsules.close()

    async def test_audit_tenant_callable(self, tmp_path: Path) -> None:
        capsules = Capsules(str(tmp_path / "test.db"))

        @capsules.audit(
            type="agent",
            tenant_id=lambda args, kwargs: kwargs.get("org", "default"),
        )
        async def my_task(prompt: str, *, org: str = "default") -> str:
            return "done"

        await my_task("hello", org="my-org")

        stored = await capsules.storage.list(tenant_id="my-org")
        assert len(stored) == 1
        await capsules.close()


# ---------------------------------------------------------------------------
# Trigger extraction
# ---------------------------------------------------------------------------


class TestTriggerExtraction:
    async def test_audit_trigger_from_first_arg(self, tmp_path: Path) -> None:
        capsules = Capsules(str(tmp_path / "test.db"))

        @capsules.audit(type="agent")
        async def my_task(prompt: str) -> str:
            return "done"

        await my_task("Write a blog post")

        stored = await capsules.storage.list()
        assert stored[0].trigger.request == "Write a blog post"
        await capsules.close()

    async def test_audit_trigger_from_named_arg(self, tmp_path: Path) -> None:
        capsules = Capsules(str(tmp_path / "test.db"))

        @capsules.audit(type="agent", trigger_from="task")
        async def my_task(task: str, model: str) -> str:
            return "done"

        await my_task("Summarize report", "gpt-4")

        stored = await capsules.storage.list()
        assert stored[0].trigger.request == "Summarize report"
        await capsules.close()

    async def test_audit_trigger_from_kwarg(self, tmp_path: Path) -> None:
        capsules = Capsules(str(tmp_path / "test.db"))

        @capsules.audit(type="agent", trigger_from="task")
        async def my_task(*, task: str) -> str:
            return "done"

        await my_task(task="Analyze data")

        stored = await capsules.storage.list()
        assert stored[0].trigger.request == "Analyze data"
        await capsules.close()


# ---------------------------------------------------------------------------
# Source
# ---------------------------------------------------------------------------


class TestSourceExtraction:
    async def test_audit_source_defaults_to_qualname(self, tmp_path: Path) -> None:
        capsules = Capsules(str(tmp_path / "test.db"))

        @capsules.audit(type="agent")
        async def my_task(prompt: str) -> str:
            return "done"

        await my_task("test")

        stored = await capsules.storage.list()
        assert "my_task" in stored[0].trigger.source
        await capsules.close()

    async def test_audit_source_custom(self, tmp_path: Path) -> None:
        capsules = Capsules(str(tmp_path / "test.db"))

        @capsules.audit(type="agent", source="custom-bot")
        async def my_task(prompt: str) -> str:
            return "done"

        await my_task("test")

        stored = await capsules.storage.list()
        assert stored[0].trigger.source == "custom-bot"
        await capsules.close()


# ---------------------------------------------------------------------------
# Context variable: capsules.current()
# ---------------------------------------------------------------------------


class TestCurrentCapsule:
    async def test_current_capsule(self, tmp_path: Path) -> None:
        capsules = Capsules(str(tmp_path / "test.db"))

        captured_capsule = None

        @capsules.audit(type="agent")
        async def my_task(prompt: str) -> str:
            nonlocal captured_capsule
            captured_capsule = capsules.current()
            return "done"

        await my_task("test")
        assert captured_capsule is not None
        assert captured_capsule.type == CapsuleType.AGENT

        await capsules.close()

    def test_current_capsule_outside(self, tmp_path: Path) -> None:
        capsules = Capsules(str(tmp_path / "test.db"))
        with pytest.raises(RuntimeError, match="No active capsule"):
            capsules.current()

    async def test_current_capsule_enrichment(self, tmp_path: Path) -> None:
        capsules = Capsules(str(tmp_path / "test.db"))

        @capsules.audit(type="agent")
        async def my_task(prompt: str) -> str:
            cap = capsules.current()
            cap.reasoning.model = "gpt-5.2"
            cap.reasoning.confidence = 0.95
            cap.context.session_id = "session-xyz"
            cap.execution.resources_used = {"tokens": 1500}
            cap.outcome.summary = "Generated content"
            return "done"

        await my_task("test")

        stored = await capsules.storage.list()
        cap = stored[0]
        assert cap.reasoning.model == "gpt-5.2"
        assert cap.reasoning.confidence == 0.95
        assert cap.context.session_id == "session-xyz"
        assert cap.execution.resources_used == {"tokens": 1500}
        assert cap.outcome.summary == "Generated content"
        await capsules.close()


# ---------------------------------------------------------------------------
# Sync function support
# ---------------------------------------------------------------------------


class TestSyncSupport:
    async def test_audit_decorator_sync(self, tmp_path: Path) -> None:
        capsules = Capsules(str(tmp_path / "test.db"))

        @capsules.audit(type="tool")
        def my_sync_task(value: int) -> int:
            return value * 2

        result = my_sync_task(21)
        assert result == 42

        # Sync functions with a running loop schedule the write as a task.
        # Wait for that task, never for a fixed time: a first store creates
        # the file, and a slow runner took longer than the 50 ms this slept.
        assert len(capsules._pending) == 1
        await asyncio.wait_for(asyncio.gather(*capsules._pending), timeout=10)
        assert not capsules._pending, "a finished write is released"

        stored = await capsules.storage.list()
        assert len(stored) >= 1
        cap = stored[0]
        assert cap.type == CapsuleType.TOOL
        assert cap.outcome.status == "success"
        assert cap.is_sealed()
        await capsules.close()

    def test_audit_decorator_sync_no_loop(self, tmp_path: Path) -> None:
        """Sync function with no running event loop still stores the capsule."""
        import subprocess
        import sys

        script = f"""
import sys
sys.path.insert(0, "src")
from qp_capsule.audit import Capsules

capsules = Capsules("{tmp_path / 'sync_test.db'}")

@capsules.audit(type="tool")
def compute(x):
    return x * 2

result = compute(21)
assert result == 42

import asyncio
count = asyncio.run(capsules.storage.count())
assert count == 1, f"Expected 1 capsule, got {{count}}"
print("SYNC_NO_LOOP_OK")
"""
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).parent.parent),
        )
        assert "SYNC_NO_LOOP_OK" in proc.stdout, (
            f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
        )


    async def test_close_waits_for_a_scheduled_write(self, tmp_path: Path) -> None:
        """RED PROOF: closing right after a sync call used to drop its capsule."""
        db = tmp_path / "test.db"
        capsules = Capsules(str(db))

        @capsules.audit(type="tool")
        def my_sync_task(value: int) -> int:
            return value * 2

        my_sync_task(1)
        await capsules.close()

        reopened = Capsules(str(db))
        try:
            assert await reopened.storage.count() == 1
        finally:
            await reopened.close()


# ---------------------------------------------------------------------------
# Timing
# ---------------------------------------------------------------------------


class TestTiming:
    async def test_audit_timing(self, tmp_path: Path) -> None:
        capsules = Capsules(str(tmp_path / "test.db"))

        @capsules.audit(type="agent")
        async def slow_task(prompt: str) -> str:
            await asyncio.sleep(0.05)
            return "done"

        await slow_task("test")

        stored = await capsules.storage.list()
        cap = stored[0]
        assert cap.execution.duration_ms >= 40
        assert cap.execution.duration_ms < 500
        await capsules.close()


# ---------------------------------------------------------------------------
# CapsuleType from string
# ---------------------------------------------------------------------------


class TestEdgeCases:
    async def test_safe_repr_unrepresentable(self, tmp_path: Path) -> None:
        """Objects that raise on str() get '<unrepresentable>'."""
        from qp_capsule.audit import _safe_repr

        class BadObj:
            def __str__(self) -> str:
                raise RuntimeError("cannot repr")

        assert _safe_repr(BadObj()) == "<unrepresentable>"

    async def test_safe_repr_truncation(self, tmp_path: Path) -> None:
        from qp_capsule.audit import _safe_repr

        long_str = "x" * 1000
        result = _safe_repr(long_str, max_length=10)
        assert result == "xxxxxxxxxx"
        assert len(result) == 10

    async def test_safe_repr_collections(self, tmp_path: Path) -> None:
        from qp_capsule.audit import _safe_repr

        assert _safe_repr([1, "two", None]) == ["1", "two", None]
        assert _safe_repr({"a": 1}) == {"a": "1"}

    async def test_safe_repr_depth_guard(self, tmp_path: Path) -> None:
        """Deeply nested structures get truncated, not stack overflow."""
        from qp_capsule.audit import _safe_repr

        nested: dict[str, Any] = {"level": 0}
        current = nested
        for i in range(50):
            current["child"] = {"level": i + 1}
            current = current["child"]

        result = _safe_repr(nested)
        assert isinstance(result, dict)

        deep: Any = result
        depth = 0
        while isinstance(deep, dict) and "child" in deep and isinstance(deep["child"], dict):
            deep = deep["child"]
            depth += 1

        assert depth <= 21
        if isinstance(deep, dict) and "child" in deep:
            assert deep["child"] == "<nested too deep>"

    async def test_safe_repr_custom_object(self, tmp_path: Path) -> None:
        """Non-primitive objects that CAN be stringified use str()."""
        from qp_capsule.audit import _safe_repr

        class MyObj:
            def __str__(self) -> str:
                return "my-repr"

        assert _safe_repr(MyObj()) == "my-repr"

    async def test_trigger_from_no_args(self, tmp_path: Path) -> None:
        """trigger_from=None with no args returns empty string."""
        capsules = Capsules(str(tmp_path / "test.db"))

        @capsules.audit(type="agent", trigger_from=None)
        async def no_args_fn() -> str:
            return "done"

        await no_args_fn()
        stored = await capsules.storage.list()
        assert stored[0].trigger.request == ""
        await capsules.close()

    async def test_trigger_from_int_out_of_range(self, tmp_path: Path) -> None:
        """trigger_from=5 with only 1 arg returns empty string."""
        capsules = Capsules(str(tmp_path / "test.db"))

        @capsules.audit(type="agent", trigger_from=5)
        async def one_arg_fn(x: str) -> str:
            return x

        await one_arg_fn("hello")
        stored = await capsules.storage.list()
        assert stored[0].trigger.request == ""
        await capsules.close()

    async def test_trigger_from_missing_kwarg(self, tmp_path: Path) -> None:
        """trigger_from='missing' with no such kwarg returns empty string."""
        capsules = Capsules(str(tmp_path / "test.db"))

        @capsules.audit(type="agent", trigger_from="missing")
        async def fn(x: str) -> str:
            return x

        await fn("hello")
        stored = await capsules.storage.list()
        assert stored[0].trigger.request == ""
        await capsules.close()

    def test_postgres_import_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """PostgreSQL URL raises clear error when asyncpg not installed."""
        import builtins

        real_import = builtins.__import__

        def mock_import(name: str, *args: object, **kwargs: object) -> object:
            if name == "qp_capsule.storage_pg":
                raise ImportError("no asyncpg")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)
        with pytest.raises(CapsuleError, match="PostgreSQL storage requires"):
            Capsules("postgresql://localhost/test")

    def test_sqlite_import_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """SQLite URL raises clear error when aiosqlite not installed."""
        import builtins

        real_import = builtins.__import__

        def mock_import(name: str, *args: object, **kwargs: object) -> object:
            if name == "qp_capsule.storage":
                raise ImportError("no aiosqlite")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)
        with pytest.raises(CapsuleError, match="SQLite storage requires"):
            Capsules()


class TestCapsuleTypeResolution:
    async def test_audit_type_from_string(self, tmp_path: Path) -> None:
        capsules = Capsules(str(tmp_path / "test.db"))

        @capsules.audit(type="chat")
        async def chat_fn(msg: str) -> str:
            return "reply"

        await chat_fn("hello")

        stored = await capsules.storage.list()
        assert stored[0].type == CapsuleType.CHAT
        await capsules.close()

    async def test_audit_type_from_enum(self, tmp_path: Path) -> None:
        capsules = Capsules(str(tmp_path / "test.db"))

        @capsules.audit(type=CapsuleType.VAULT)
        async def vault_fn(doc: str) -> str:
            return "stored"

        await vault_fn("mydoc")

        stored = await capsules.storage.list()
        assert stored[0].type == CapsuleType.VAULT
        await capsules.close()
