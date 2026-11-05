# Copyright 2026 Quantum Pipes Technologies, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Patent Pending — See PATENTS.md for details.
# Licensed under the Apache License, Version 2.0 with patent grant (Section 3).

"""
Audit: The high-level API.

One class, one decorator, one context variable. The cryptography, storage,
chaining, and error handling become invisible.

    from qp_capsule import Capsules

    capsules = Capsules()

    @capsules.audit(type="agent")
    async def run_agent(task: str):
        cap = capsules.current()
        cap.reasoning.model = "gpt-4o"
        result = await llm.complete(task)
        return result
"""

from __future__ import annotations

import asyncio
import contextvars
import functools
import inspect
import logging
import time
from pathlib import Path
from typing import Any, Callable, TypeVar

from qp_capsule.capsule import (
    AuthoritySection,
    Capsule,
    CapsuleType,
    ContextSection,
    ExecutionSection,
    OutcomeSection,
    ReasoningSection,
    TriggerSection,
)
from qp_capsule.exceptions import CapsuleError
from qp_capsule.protocol import CapsuleStorageProtocol

logger = logging.getLogger("qp_capsule.audit")

F = TypeVar("F", bound=Callable[..., Any])

_current_capsule: contextvars.ContextVar[Capsule | None] = contextvars.ContextVar(
    "qp_capsule_current", default=None
)


def _resolve_capsule_type(value: str | CapsuleType) -> CapsuleType:
    """Convert a string to CapsuleType, passing through if already enum."""
    if isinstance(value, CapsuleType):
        return value
    return CapsuleType(value)


def _safe_repr(value: Any, max_length: int = 500, _depth: int = 0) -> Any:
    """Safely represent a value for capsule storage."""
    if _depth > 20:
        return "<nested too deep>"
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        s = str(value)
        return s[:max_length] if len(s) > max_length else s
    if isinstance(value, dict):
        return {str(k): _safe_repr(v, max_length, _depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_safe_repr(v, max_length, _depth + 1) for v in value]
    try:
        s = str(value)
        return s[:max_length] if len(s) > max_length else s
    except Exception:
        return "<unrepresentable>"


def _extract_trigger_request(
    trigger_from: str | int | None,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    sig: inspect.Signature,
) -> str:
    """Extract the trigger request from function arguments."""
    if trigger_from is None:
        if args:
            return _safe_repr(args[0], 500) or ""
        return ""

    if isinstance(trigger_from, int):
        if trigger_from < len(args):
            return _safe_repr(args[trigger_from], 500) or ""
        return ""

    if trigger_from in kwargs:
        return _safe_repr(kwargs[trigger_from], 500) or ""

    params = list(sig.parameters.keys())
    if trigger_from in params:
        idx = params.index(trigger_from)
        if idx < len(args):
            return _safe_repr(args[idx], 500) or ""

    return ""


def _extract_tenant_id(
    tenant_from: str | None,
    tenant_id: str | Callable[..., str] | None,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> str | None:
    """Resolve the tenant_id from decorator parameters."""
    if tenant_from is not None:
        return kwargs.get(tenant_from) or None

    if tenant_id is not None:
        if callable(tenant_id):
            return tenant_id(args, kwargs)
        return tenant_id

    return None


class Capsules:
    """
    The single entry point for capsule audit trails.

    Owns storage, chain, and seal internally. Provides ``@audit()``
    decorator and ``current()`` context variable for zero-boilerplate
    integration.

        capsules = Capsules()                              # SQLite
        capsules = Capsules("postgresql://user:pw@host/db") # PostgreSQL
        capsules = Capsules(storage=my_backend)             # Custom
    """

    def __init__(
        self,
        url: str | None = None,
        *,
        storage: CapsuleStorageProtocol | None = None,
    ) -> None:
        from qp_capsule.seal import Seal

        resolved_storage: CapsuleStorageProtocol | None = None

        if storage is not None:
            resolved_storage = storage
        elif url is not None and url.startswith("postgresql"):
            try:
                from qp_capsule.storage_pg import PostgresCapsuleStorage
            except ImportError as exc:
                raise CapsuleError(
                    "PostgreSQL storage requires: pip install qp-capsule[postgres]"
                ) from exc
            resolved_storage = PostgresCapsuleStorage(url)  # pragma: no cover
        else:
            try:
                from qp_capsule.storage import CapsuleStorage
            except ImportError as exc:
                raise CapsuleError(
                    "SQLite storage requires: pip install qp-capsule[storage]"
                ) from exc
            if url is not None:
                resolved_storage = CapsuleStorage(Path(url))
            else:
                resolved_storage = CapsuleStorage()

        if resolved_storage is None:  # pragma: no cover — defensive; all branches assign
            raise CapsuleError("Storage backend could not be initialized")
        self._storage: CapsuleStorageProtocol = resolved_storage

        from qp_capsule.chain import CapsuleChain

        self._seal = Seal()
        self._chain = CapsuleChain(self._storage)
        # Writes a sync function scheduled on a running loop. The loop holds only
        # a weak reference to a task, so an unreferenced one can be collected
        # before it stores its capsule; holding it here also lets close() wait.
        self._pending: set[asyncio.Task[Any]] = set()

    @property
    def storage(self) -> CapsuleStorageProtocol:
        """The underlying storage backend."""
        return self._storage

    @property
    def chain(self) -> Any:
        """The CapsuleChain instance."""
        return self._chain

    @property
    def seal(self) -> Any:
        """The Seal instance."""
        return self._seal

    def current(self) -> Capsule:
        """
        Get the active Capsule for the current execution context.

        Only valid inside an ``@audit()`` decorated function.

        Raises:
            RuntimeError: If called outside a decorated function.
        """
        capsule = _current_capsule.get()
        if capsule is None:
            raise RuntimeError(
                "No active capsule — are you inside an @audit decorated function?"
            )
        return capsule

    async def close(self) -> None:
        """Wait for scheduled capsule writes, then release storage resources."""
        if self._pending:
            await asyncio.gather(*self._pending, return_exceptions=True)
        await self._storage.close()

    def audit(
        self,
        *,
        type: str | CapsuleType,
        tenant_from: str | None = None,
        tenant_id: str | Callable[..., str] | None = None,
        trigger_from: str | int | None = 0,
        source: str | None = None,
        domain: str = "agents",
        swallow_errors: bool = True,
    ) -> Callable[[F], F]:
        """
        Decorator that wraps a function with automatic Capsule audit.

        Args:
            type: Capsule type (e.g. ``"agent"``, ``"tool"``,
                ``CapsuleType.AGENT``).
            tenant_from: Kwarg name to extract ``tenant_id`` from.
            tenant_id: Static tenant string or callable
                ``(args, kwargs) -> str``.
            trigger_from: Arg name or position for ``trigger.request``.
                Defaults to position ``0`` (first positional arg).
            source: Static ``trigger.source``. Defaults to the function's
                ``__qualname__``.
            domain: Capsule domain. Defaults to ``"agents"``.
            swallow_errors: If ``True`` (default), capsule failures are
                logged and swallowed. If ``False``, they propagate.
        """
        capsule_type = _resolve_capsule_type(type)

        def decorator(fn: F) -> F:
            fn_source = source or fn.__qualname__
            sig = inspect.signature(fn)

            if inspect.iscoroutinefunction(fn):

                @functools.wraps(fn)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    capsule = Capsule(
                        type=capsule_type,
                        domain=domain,
                        trigger=TriggerSection(
                            type="agent",
                            source=fn_source,
                            request=_extract_trigger_request(
                                trigger_from, args, kwargs, sig
                            ),
                        ),
                        context=ContextSection(agent_id=fn.__qualname__),
                        reasoning=ReasoningSection(),
                        authority=AuthoritySection(type="autonomous"),
                        execution=ExecutionSection(),
                        outcome=OutcomeSection(),
                    )

                    token = _current_capsule.set(capsule)
                    start = time.monotonic()
                    error: BaseException | None = None

                    try:
                        result = await fn(*args, **kwargs)
                        capsule.outcome.status = "success"
                        capsule.outcome.result = _safe_repr(result)
                        return result
                    except BaseException as exc:
                        error = exc
                        capsule.outcome.status = "failure"
                        capsule.outcome.error = str(exc)
                        raise
                    finally:
                        elapsed_ms = int((time.monotonic() - start) * 1000)
                        capsule.execution.duration_ms = elapsed_ms
                        _current_capsule.reset(token)

                        try:
                            resolved_tenant = _extract_tenant_id(
                                tenant_from, tenant_id, args, kwargs
                            )
                            await self._chain.seal_and_store(
                                capsule,
                                seal=self._seal,
                                tenant_id=resolved_tenant,
                            )
                        except Exception as seal_err:
                            if swallow_errors:
                                logger.warning(
                                    "Capsule audit failed (swallowed): %s", seal_err
                                )
                            else:
                                if error is None:
                                    raise

                return async_wrapper  # type: ignore[return-value]

            else:

                @functools.wraps(fn)
                def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                    capsule = Capsule(
                        type=capsule_type,
                        domain=domain,
                        trigger=TriggerSection(
                            type="agent",
                            source=fn_source,
                            request=_extract_trigger_request(
                                trigger_from, args, kwargs, sig
                            ),
                        ),
                        context=ContextSection(agent_id=fn.__qualname__),
                        reasoning=ReasoningSection(),
                        authority=AuthoritySection(type="autonomous"),
                        execution=ExecutionSection(),
                        outcome=OutcomeSection(),
                    )

                    token = _current_capsule.set(capsule)
                    start = time.monotonic()
                    error: BaseException | None = None

                    try:
                        result = fn(*args, **kwargs)
                        capsule.outcome.status = "success"
                        capsule.outcome.result = _safe_repr(result)
                        return result
                    except BaseException as exc:
                        error = exc
                        capsule.outcome.status = "failure"
                        capsule.outcome.error = str(exc)
                        raise
                    finally:
                        elapsed_ms = int((time.monotonic() - start) * 1000)
                        capsule.execution.duration_ms = elapsed_ms
                        _current_capsule.reset(token)

                        try:
                            resolved_tenant = _extract_tenant_id(
                                tenant_from, tenant_id, args, kwargs
                            )
                            _coro = self._chain.seal_and_store(
                                capsule,
                                seal=self._seal,
                                tenant_id=resolved_tenant,
                            )
                            try:
                                loop = asyncio.get_running_loop()
                            except RuntimeError:
                                loop = None

                            if loop is not None and loop.is_running():
                                task = loop.create_task(_coro)
                                self._pending.add(task)
                                task.add_done_callback(self._pending.discard)
                            else:
                                asyncio.run(_coro)
                        except Exception as seal_err:
                            if swallow_errors:
                                logger.warning(
                                    "Capsule audit failed (swallowed): %s", seal_err
                                )
                            else:
                                if error is None:
                                    raise

                return sync_wrapper  # type: ignore[return-value]

        return decorator
