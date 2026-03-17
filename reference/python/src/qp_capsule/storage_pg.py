# Copyright 2026 Quantum Pipes Technologies, LLC
# SPDX-License-Identifier: Apache-2.0

"""
PostgreSQL Capsule Storage.

Stores capsules in PostgreSQL with `quantumpipes_capsules` table prefix.
Shares the same database as the Vault when both are configured.

Satisfies CapsuleStorageProtocol — drop-in replacement for CapsuleStorage (SQLite).
Adds domain filtering and multi-tenant isolation beyond the base protocol.

Requires: pip install qp-capsule[postgres]

Usage:
    from qp_capsule.storage_pg import PostgresCapsuleStorage

    storage = PostgresCapsuleStorage("postgresql+asyncpg://user:pass@localhost/myapp")
    await storage.store(capsule)
    capsule = await storage.get(capsule_id)
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import datetime
from uuid import UUID

from sqlalchemy import DDL, Integer, String, Text, UniqueConstraint, desc, event, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from qp_capsule.capsule import Capsule, CapsuleType
from qp_capsule.exceptions import StorageError


class PGBase(DeclarativeBase):
    """SQLAlchemy declarative base for PostgreSQL capsule storage."""

    pass


class CapsuleModelPG(PGBase):
    """
    PostgreSQL model for Capsules.

    Table: quantumpipes_capsules (prefixed to avoid collisions)
    """

    __tablename__ = "quantumpipes_capsules"
    __table_args__ = (
        UniqueConstraint("tenant_id", "sequence", name="uq_capsule_tenant_sequence"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    type: Mapped[str] = mapped_column(String(20))
    sequence: Mapped[int] = mapped_column(Integer, index=True)
    previous_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    data: Mapped[str] = mapped_column(Text)  # JSON serialized Capsule
    hash: Mapped[str] = mapped_column(String(64), index=True)
    signature: Mapped[str] = mapped_column(Text)  # Ed25519 (classical)
    signature_pq: Mapped[str] = mapped_column(Text, default="")  # ML-DSA-65 (post-quantum)
    signed_at: Mapped[str | None] = mapped_column(String(40), nullable=True)
    signed_by: Mapped[str | None] = mapped_column(String(32), nullable=True)
    session_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    domain: Mapped[str] = mapped_column(String(50), default="agents", index=True)
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)


event.listen(
    CapsuleModelPG.__table__,
    "after_create",
    DDL(  # type: ignore[no-untyped-call]
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_capsule_global_sequence "
        "ON quantumpipes_capsules (sequence) WHERE tenant_id IS NULL"
    ).execute_if(dialect="postgresql"),
)


class PostgresCapsuleStorage:
    """
    Capsule storage using PostgreSQL.

    Drop-in replacement for CapsuleStorage (SQLite). Same interface,
    PostgreSQL backend. Table is `quantumpipes_capsules`.

    Usage:
        storage = PostgresCapsuleStorage("postgresql+asyncpg://user:pass@localhost/myapp")
        await storage.store(capsule)
        capsule = await storage.get(capsule_id)
        capsules = await storage.list(limit=10)
    """

    def __init__(self, database_url: str) -> None:
        """
        Initialize PostgreSQL capsule storage.

        Args:
            database_url: PostgreSQL connection string.
                Automatically converts to asyncpg driver if needed.
        """
        if "asyncpg" not in database_url and "postgresql" in database_url:
            database_url = database_url.replace("postgresql://", "postgresql+asyncpg://")
        self.database_url = database_url
        self._engine = create_async_engine(
            database_url,
            echo=False,
            pool_size=5,
            max_overflow=10,
        )
        self._session_factory = async_sessionmaker(
            self._engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
        self._initialized = False

    async def _ensure_db(self) -> None:
        """Create tables if they don't exist."""
        if not self._initialized:
            async with self._engine.begin() as conn:
                await conn.run_sync(PGBase.metadata.create_all)
            self._initialized = True

    async def store(self, capsule: Capsule, tenant_id: str | None = None) -> Capsule:
        """
        Store a sealed Capsule.

        Args:
            capsule: The sealed Capsule to store
            tenant_id: Optional tenant for multi-tenant isolation

        Returns:
            The stored Capsule

        Raises:
            StorageError: If Capsule is not sealed or storage fails
        """
        if not capsule.is_sealed():
            raise StorageError("Cannot store unsealed Capsule")

        await self._ensure_db()

        try:
            model = CapsuleModelPG(
                id=str(capsule.id),
                type=capsule.type.value if isinstance(capsule.type, CapsuleType) else capsule.type,
                sequence=capsule.sequence,
                previous_hash=capsule.previous_hash,
                data=json.dumps(capsule.to_dict(), default=str),
                hash=capsule.hash or "",
                signature=capsule.signature.hex()
                if isinstance(capsule.signature, bytes)
                else (capsule.signature or ""),
                signature_pq=capsule.signature_pq.hex()
                if isinstance(capsule.signature_pq, bytes)
                else (capsule.signature_pq or ""),
                signed_at=capsule.signed_at.isoformat() if capsule.signed_at else "",
                signed_by=capsule.signed_by or "",
                session_id=getattr(capsule.context, "session_id", None)
                if capsule.context
                else None,
                domain=capsule.domain,
                tenant_id=tenant_id,
            )

            async with self._session_factory() as session:
                session.add(model)
                await session.commit()

            return capsule

        except Exception as e:
            raise StorageError(
                f"Failed to store capsule: {type(e).__name__}"
            ) from e

    async def get(
        self, capsule_id: str | UUID, tenant_id: str | None = None
    ) -> Capsule | None:
        """
        Retrieve a Capsule by ID.

        Args:
            capsule_id: Full or partial Capsule ID
            tenant_id: If provided, only returns the Capsule if it belongs to this tenant

        Returns:
            The Capsule, or None if not found
        """
        await self._ensure_db()

        capsule_id_str = str(capsule_id)

        async with self._session_factory() as session:
            query = select(CapsuleModelPG).where(
                CapsuleModelPG.id == capsule_id_str
            )
            if tenant_id is not None:
                query = query.where(CapsuleModelPG.tenant_id == tenant_id)

            result = await session.execute(query)
            model = result.scalar_one_or_none()

            if model is None and len(capsule_id_str) < 36:
                query = select(CapsuleModelPG).where(
                    CapsuleModelPG.id.startswith(capsule_id_str)
                )
                if tenant_id is not None:
                    query = query.where(CapsuleModelPG.tenant_id == tenant_id)

                result = await session.execute(query)
                model = result.scalar_one_or_none()

            if model is None:
                return None

            return self._to_capsule(model)

    async def list(
        self,
        limit: int = 100,
        offset: int = 0,
        type_filter: CapsuleType | str | None = None,
        tenant_id: str | None = None,
        domain: str | None = None,
        session_id: str | None = None,
    ) -> Sequence[Capsule]:
        """
        List Capsules with optional filtering.

        Args:
            limit: Maximum number of Capsules to return
            offset: Number of Capsules to skip
            type_filter: Filter by Capsule type
            tenant_id: Filter by tenant for multi-tenant isolation
            domain: Filter by domain (e.g., "vault", "agents", "chat")
            session_id: Filter by session ID

        Returns:
            List of Capsules ordered by sequence (newest first)
        """
        await self._ensure_db()

        async with self._session_factory() as session:
            query = select(CapsuleModelPG).order_by(desc(CapsuleModelPG.sequence))

            if type_filter is not None:
                type_str = (
                    type_filter.value if isinstance(type_filter, CapsuleType) else type_filter
                )
                query = query.where(CapsuleModelPG.type == type_str)

            if domain is not None:
                query = query.where(CapsuleModelPG.domain == domain)

            if session_id is not None:
                query = query.where(CapsuleModelPG.session_id == session_id)

            if tenant_id is not None:
                query = query.where(CapsuleModelPG.tenant_id == tenant_id)

            query = query.limit(limit).offset(offset)
            result = await session.execute(query)
            models = result.scalars().all()

            return [self._to_capsule(m) for m in models]

    async def count(
        self,
        type_filter: CapsuleType | str | None = None,
        tenant_id: str | None = None,
        domain: str | None = None,
    ) -> int:
        """
        Count Capsules with optional filtering.

        Args:
            type_filter: Filter by Capsule type
            tenant_id: Filter by tenant for multi-tenant isolation
            domain: Filter by domain

        Returns:
            Number of matching Capsules
        """
        from sqlalchemy import func

        await self._ensure_db()

        async with self._session_factory() as session:
            query = select(func.count()).select_from(CapsuleModelPG)

            if type_filter is not None:
                type_str = (
                    type_filter.value if isinstance(type_filter, CapsuleType) else type_filter
                )
                query = query.where(CapsuleModelPG.type == type_str)

            if domain is not None:
                query = query.where(CapsuleModelPG.domain == domain)

            if tenant_id is not None:
                query = query.where(CapsuleModelPG.tenant_id == tenant_id)

            result = await session.execute(query)
            return result.scalar_one()

    async def get_latest(self, tenant_id: str | None = None) -> Capsule | None:
        """
        Get the most recent Capsule.

        Args:
            tenant_id: If provided, returns the latest for this tenant only
        """
        await self._ensure_db()

        async with self._session_factory() as session:
            query = select(CapsuleModelPG).order_by(desc(CapsuleModelPG.sequence))
            if tenant_id is not None:
                query = query.where(CapsuleModelPG.tenant_id == tenant_id)
            query = query.limit(1)
            result = await session.execute(query)
            model = result.scalar_one_or_none()

            if model is None:
                return None

            return self._to_capsule(model)

    def _to_capsule(self, model: CapsuleModelPG) -> Capsule:
        """Convert model to Capsule, restoring seal info from columns."""
        capsule = Capsule.from_dict(json.loads(model.data))
        capsule.hash = model.hash
        capsule.signature = model.signature
        capsule.signature_pq = model.signature_pq or ""
        capsule.signed_at = datetime.fromisoformat(model.signed_at) if model.signed_at else None
        capsule.signed_by = model.signed_by or ""
        return capsule

    async def get_all_ordered(self, tenant_id: str | None = None) -> Sequence[Capsule]:
        """
        Get all Capsules in sequence order (for chain verification).

        Args:
            tenant_id: If provided, returns only this tenant's Capsules.
        """
        await self._ensure_db()

        async with self._session_factory() as session:
            query = select(CapsuleModelPG).order_by(CapsuleModelPG.sequence)
            if tenant_id is not None:
                query = query.where(CapsuleModelPG.tenant_id == tenant_id)
            result = await session.execute(query)
            models = result.scalars().all()
            return [self._to_capsule(m) for m in models]

    async def close(self) -> None:
        """Close the database connection."""
        await self._engine.dispose()


CapsuleStoragePG = PostgresCapsuleStorage

__all__ = [
    "PostgresCapsuleStorage",
    "CapsuleStoragePG",
    "CapsuleModelPG",
]
