# Copyright 2026 Quantum Pipes Technologies, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Patent Pending — See PATENTS.md for details.
# Licensed under the Apache License, Version 2.0 with patent grant (Section 3).

"""
Storage: Capsule persistence.

SQLite by default - zero external dependencies.
Capsules are stored with their full content and seal.

Features:
    - Zero-dependency startup (SQLite)
    - Capsules survive restart
    - Query by time, type, sequence
    - Chain ordering preserved
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import Integer, String, Text, UniqueConstraint, desc, func, select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from qp_capsule.capsule import Capsule, CapsuleType
from qp_capsule.exceptions import StorageError
from qp_capsule.paths import default_db_path


class Base(DeclarativeBase):
    """SQLAlchemy declarative base."""

    pass


class CapsuleModel(Base):
    """
    SQLAlchemy model for Capsules.

    Stores the full Capsule including seal information.
    """

    __tablename__ = "capsules"
    __table_args__ = (
        UniqueConstraint("sequence", name="uq_capsule_sequence"),
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
    # v1.0.0: Session tracking for conversation queries
    session_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)


class CapsuleStorage:
    """
    Capsule storage using SQLite.

    Zero external dependencies. Works out of the box.

    Usage:
        storage = CapsuleStorage()
        await storage.store(capsule)
        capsule = await storage.get(capsule_id)
        capsules = await storage.list(limit=10)
    """

    def __init__(self, db_path: Path | None = None, **engine_kwargs: Any):
        """
        Initialize storage.

        Args:
            db_path: Path to SQLite database file.
                     Defaults to $QUANTUMPIPES_DATA_DIR/capsules.db or ~/.quantumpipes/capsules.db
            **engine_kwargs: Forwarded to ``create_async_engine`` (e.g. ``poolclass``).
        """
        self.db_path = db_path or default_db_path()
        self._engine_kwargs = engine_kwargs
        self._engine: AsyncEngine | None = None
        self._session_factory: async_sessionmaker[AsyncSession] | None = None

    def _get_session_factory(self) -> async_sessionmaker[AsyncSession]:
        """Return the session factory, raising if database is not initialized."""
        if self._session_factory is None:
            raise StorageError("Database not initialized — call _ensure_db() first")
        return self._session_factory

    async def _ensure_db(self) -> None:
        """Initialize database if needed."""
        if self._engine is None:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

            self._engine = create_async_engine(
                f"sqlite+aiosqlite:///{self.db_path}",
                echo=False,
                **self._engine_kwargs,
            )

            async with self._engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

            self._session_factory = async_sessionmaker(
                self._engine,
                class_=AsyncSession,
                expire_on_commit=False,
            )

    async def store(self, capsule: Capsule, tenant_id: str | None = None) -> Capsule:
        """
        Store a sealed Capsule.

        Args:
            capsule: The sealed Capsule to store
            tenant_id: Accepted for interface compatibility; ignored by SQLite storage.

        Returns:
            The stored Capsule

        Raises:
            StorageError: If Capsule is not sealed or storage fails
        """
        if not capsule.is_sealed():
            raise StorageError("Cannot store unsealed Capsule")

        await self._ensure_db()
        session_factory = self._get_session_factory()

        model = CapsuleModel(
            id=str(capsule.id),
            type=capsule.type.value,
            sequence=capsule.sequence,
            previous_hash=capsule.previous_hash,
            data=json.dumps(capsule.to_dict()),
            hash=capsule.hash,
            signature=capsule.signature,
            signature_pq=capsule.signature_pq,
            signed_at=capsule.signed_at.isoformat() if capsule.signed_at else None,
            signed_by=capsule.signed_by,
            session_id=capsule.context.session_id,  # v1.0.0: Enable session queries
        )

        async with session_factory() as session:
            session.add(model)
            await session.commit()

        return capsule

    async def get(self, capsule_id: UUID | str, tenant_id: str | None = None) -> Capsule | None:
        """
        Get a Capsule by ID.

        Args:
            capsule_id: The Capsule UUID
            tenant_id: Accepted for interface compatibility; ignored by SQLite storage.

        Returns:
            The Capsule or None if not found
        """
        await self._ensure_db()
        session_factory = self._get_session_factory()

        async with session_factory() as session:
            result = await session.get(CapsuleModel, str(capsule_id))
            if result:
                return self._to_capsule(result)
            return None

    async def get_by_hash(self, hash_value: str) -> Capsule | None:
        """
        Get a Capsule by its hash.

        Args:
            hash_value: The SHA3-256 hash

        Returns:
            The Capsule or None if not found
        """
        await self._ensure_db()
        session_factory = self._get_session_factory()

        async with session_factory() as session:
            result = await session.execute(
                select(CapsuleModel).where(CapsuleModel.hash == hash_value)
            )
            model = result.scalar_one_or_none()
            if model:
                return self._to_capsule(model)
            return None

    async def get_latest(self, tenant_id: str | None = None) -> Capsule | None:
        """
        Get the most recent Capsule (chain head).

        Args:
            tenant_id: Accepted for interface compatibility; ignored by SQLite storage.

        Returns:
            The latest Capsule or None if storage is empty
        """
        await self._ensure_db()
        session_factory = self._get_session_factory()

        async with session_factory() as session:
            result = await session.execute(
                select(CapsuleModel).order_by(desc(CapsuleModel.sequence)).limit(1)
            )
            model = result.scalar_one_or_none()
            if model:
                return self._to_capsule(model)
            return None

    async def get_all_ordered(self, tenant_id: str | None = None) -> Sequence[Capsule]:
        """
        Get all Capsules in sequence order (for chain verification).

        Args:
            tenant_id: Accepted for interface compatibility; ignored by SQLite storage.

        Returns:
            List of Capsules ordered by sequence
        """
        await self._ensure_db()
        session_factory = self._get_session_factory()

        async with session_factory() as session:
            result = await session.execute(select(CapsuleModel).order_by(CapsuleModel.sequence))
            models = result.scalars().all()
            return [self._to_capsule(m) for m in models]

    async def list(
        self,
        limit: int = 100,
        offset: int = 0,
        type_filter: CapsuleType | None = None,
        tenant_id: str | None = None,
    ) -> Sequence[Capsule]:
        """
        List Capsules with pagination.

        Args:
            limit: Maximum number of Capsules to return
            offset: Number of Capsules to skip
            type_filter: Optional filter by Capsule type
            tenant_id: Accepted for interface compatibility; ignored by SQLite storage.

        Returns:
            List of Capsules (most recent first)
        """
        await self._ensure_db()
        session_factory = self._get_session_factory()

        async with session_factory() as session:
            query = select(CapsuleModel).order_by(desc(CapsuleModel.sequence))

            if type_filter:
                query = query.where(CapsuleModel.type == type_filter.value)

            query = query.limit(limit).offset(offset)

            result = await session.execute(query)
            models = result.scalars().all()
            return [self._to_capsule(m) for m in models]

    async def list_by_session(self, session_id: str) -> Sequence[Capsule]:
        """
        List all Capsules in a conversation session.

        Args:
            session_id: The session ID to filter by (must be valid UUID format)

        Returns:
            List of Capsules in chronological order (oldest first)
        """
        # Validate UUID format (defense-in-depth)
        if session_id:
            try:
                UUID(session_id)
            except ValueError:
                return []  # Invalid format returns empty, not error

        await self._ensure_db()
        session_factory = self._get_session_factory()

        async with session_factory() as session:
            query = (
                select(CapsuleModel)
                .where(CapsuleModel.session_id == session_id)
                .order_by(CapsuleModel.sequence)  # Chronological order
            )

            result = await session.execute(query)
            models = result.scalars().all()
            return [self._to_capsule(m) for m in models]

    async def count(
        self, type_filter: CapsuleType | None = None, tenant_id: str | None = None
    ) -> int:
        """
        Count Capsules.

        Args:
            type_filter: Optional filter by Capsule type
            tenant_id: Accepted for interface compatibility; ignored by SQLite storage.

        Returns:
            Number of Capsules
        """
        await self._ensure_db()
        session_factory = self._get_session_factory()

        async with session_factory() as session:
            query = select(func.count(CapsuleModel.id))

            if type_filter:
                query = query.where(CapsuleModel.type == type_filter.value)

            result = await session.execute(query)
            count: int = result.scalar_one()
            return count

    def _to_capsule(self, model: CapsuleModel) -> Capsule:
        """
        Convert SQLAlchemy model to Capsule.

        Args:
            model: The database model

        Returns:
            The Capsule domain object
        """
        from datetime import datetime

        data = json.loads(model.data)
        capsule = Capsule.from_dict(data)

        # Restore seal information
        capsule.hash = model.hash
        capsule.signature = model.signature
        capsule.signature_pq = model.signature_pq or ""
        capsule.signed_at = datetime.fromisoformat(model.signed_at) if model.signed_at else None
        capsule.signed_by = model.signed_by or ""

        return capsule

    async def close(self) -> None:
        """Close the database connection."""
        if self._engine:
            await self._engine.dispose()
            self._engine = None
            self._session_factory = None
