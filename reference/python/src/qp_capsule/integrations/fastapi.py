# Copyright 2026 Quantum Pipes Technologies, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Patent Pending — See PATENTS.md for details.
# Licensed under the Apache License, Version 2.0 with patent grant (Section 3).

"""
FastAPI integration for Capsule audit trails.

Adds three read-only endpoints for inspecting the capsule chain:
    - GET {prefix}/         — List capsules (paginated, filterable)
    - GET {prefix}/{id}     — Get a single capsule
    - GET {prefix}/verify   — Verify chain integrity

Usage:
    from fastapi import FastAPI
    from qp_capsule import Capsules
    from qp_capsule.integrations.fastapi import mount_capsules

    app = FastAPI()
    capsules = Capsules("postgresql://...")
    mount_capsules(app, capsules, prefix="/api/v1/capsules")

FastAPI is NOT a hard dependency of qp-capsule. This module imports
it lazily and raises a clear error if it's not installed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from qp_capsule.audit import Capsules


def mount_capsules(
    app: Any,
    capsules: Capsules,
    prefix: str = "/api/v1/capsules",
) -> None:
    """
    Mount capsule audit endpoints onto a FastAPI application.

    These endpoints are **read-only** (list, get, verify). They do NOT
    add authentication or authorization — that is the consumer's
    responsibility. In production, protect these routes with your
    application's auth middleware (e.g. ``Depends(get_current_user)``
    on the FastAPI app or a sub-application).

    Args:
        app: A FastAPI application instance.
        capsules: An initialized ``Capsules`` instance.
        prefix: URL prefix for the capsule routes.

    Raises:
        CapsuleError: If FastAPI is not installed.
    """
    try:
        from fastapi import APIRouter  # noqa: I001  # type: ignore[import-not-found,unused-ignore]
        from fastapi import HTTPException, Query
    except ImportError as exc:
        from qp_capsule.exceptions import CapsuleError

        raise CapsuleError(
            "FastAPI integration requires fastapi: pip install fastapi"
        ) from exc

    from qp_capsule.capsule import CapsuleType

    router: Any = APIRouter(tags=["capsules"])

    @router.get("/")  # type: ignore[untyped-decorator]
    async def list_capsules(
        limit: int = Query(default=20, ge=1, le=100),
        offset: int = Query(default=0, ge=0),
        type: str | None = Query(default=None),
        tenant_id: str | None = Query(default=None),
    ) -> dict[str, Any]:
        type_filter = CapsuleType(type) if type else None
        items = await capsules.storage.list(
            limit=limit,
            offset=offset,
            type_filter=type_filter,
            tenant_id=tenant_id,
        )
        total = await capsules.storage.count(
            type_filter=type_filter,
            tenant_id=tenant_id,
        )
        return {
            "capsules": [c.to_sealed_dict() for c in items],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    @router.get("/verify")  # type: ignore[untyped-decorator]
    async def verify_chain(
        tenant_id: str | None = Query(default=None),
    ) -> dict[str, Any]:
        result = await capsules.chain.verify(tenant_id=tenant_id)
        return {
            "valid": result.valid,
            "capsules_verified": result.capsules_verified,
            "error": result.error,
            "broken_at": result.broken_at,
        }

    @router.get("/{capsule_id}")  # type: ignore[untyped-decorator]
    async def get_capsule(
        capsule_id: str,
        tenant_id: str | None = Query(default=None),
    ) -> dict[str, Any]:
        capsule = await capsules.storage.get(capsule_id, tenant_id=tenant_id)
        if capsule is None:
            raise HTTPException(status_code=404, detail="Capsule not found")
        return capsule.to_sealed_dict()

    app.include_router(router, prefix=prefix)
