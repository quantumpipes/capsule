"""
Tests for signed_at / signed_by column width fix.

Validates that timezone-aware datetime.isoformat() values (32 chars)
fit within the widened String(40) columns, and that signed_by handles
both legacy hex prefix (16 chars) and keyring qp_key_XXXX formats.

Regression tests for: String(30) overflow on PostgreSQL when storing
capsule.signed_at.isoformat() for UTC-aware datetimes.
"""

from datetime import UTC, datetime, timedelta, timezone

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from qp_capsule.capsule import Capsule
from qp_capsule.keyring import Keyring
from qp_capsule.seal import Seal
from qp_capsule.storage import CapsuleModel, CapsuleStorage
from qp_capsule.storage_pg import CapsuleModelPG, PostgresCapsuleStorage

# =========================================================================
# Schema — Column width declarations
# =========================================================================


class TestSignedAtSchemaWidth:
    """Verify both models declare signed_at as String(40)."""

    def test_sqlite_model_column_width(self):
        col = CapsuleModel.__table__.columns["signed_at"]
        assert col.type.length == 40

    def test_pg_model_column_width(self):
        col = CapsuleModelPG.__table__.columns["signed_at"]
        assert col.type.length == 40


class TestSignedBySchemaWidth:
    """Verify both models declare signed_by as String(32)."""

    def test_sqlite_model_column_width(self):
        col = CapsuleModel.__table__.columns["signed_by"]
        assert col.type.length == 32

    def test_pg_model_column_width(self):
        col = CapsuleModelPG.__table__.columns["signed_by"]
        assert col.type.length == 32


# =========================================================================
# Isoformat length — prove the old limit was too narrow
# =========================================================================


class TestIsoformatLengths:
    """Demonstrate that timezone-aware isoformat exceeds the old String(30)."""

    def test_utc_isoformat_is_32_chars(self):
        dt = datetime(2026, 3, 17, 5, 24, 42, 485699, tzinfo=timezone.utc)
        iso = dt.isoformat()
        assert len(iso) == 32
        assert iso.endswith("+00:00")

    def test_positive_offset_isoformat_is_32_chars(self):
        tz = timezone(timedelta(hours=5, minutes=30))
        dt = datetime(2026, 3, 17, 10, 54, 42, 485450, tzinfo=tz)
        assert len(dt.isoformat()) == 32

    def test_negative_offset_isoformat_is_32_chars(self):
        tz = timezone(timedelta(hours=-7))
        dt = datetime(2026, 3, 17, 22, 24, 42, 123456, tzinfo=tz)
        assert len(dt.isoformat()) == 32

    def test_naive_isoformat_is_26_chars(self):
        dt = datetime(2026, 3, 17, 5, 24, 42, 485699)
        assert len(dt.isoformat()) == 26

    def test_seal_produces_utc_aware_datetime(self, tmp_path):
        """Seal.seal() stamps signed_at with UTC — the 32-char variant."""
        seal = Seal(key_path=tmp_path / "key")
        capsule = Capsule()
        seal.seal(capsule)

        assert capsule.signed_at is not None
        assert capsule.signed_at.tzinfo is not None
        assert len(capsule.signed_at.isoformat()) == 32

    def test_all_variants_fit_within_40(self):
        """Every plausible isoformat output fits String(40)."""
        variants = [
            datetime(2026, 3, 17, 5, 24, 42, 485699, tzinfo=timezone.utc),
            datetime(2026, 3, 17, 10, 54, 42, 0, tzinfo=timezone(timedelta(hours=5, minutes=30))),
            datetime(2026, 3, 17, 22, 24, 42, 123456, tzinfo=timezone(timedelta(hours=-12))),
            datetime(2026, 3, 17, 5, 24, 42, 485699),
            datetime(9999, 12, 31, 23, 59, 59, 999999, tzinfo=timezone.utc),
        ]
        for dt in variants:
            iso = dt.isoformat()
            assert len(iso) <= 40, f"{iso!r} is {len(iso)} chars"

    def test_old_limit_would_truncate(self):
        """Confirm String(30) would have truncated UTC isoformat."""
        dt = datetime.now(UTC)
        iso = dt.isoformat()
        assert len(iso) > 30, "UTC isoformat must exceed old String(30) limit"


# =========================================================================
# signed_by length — both fingerprint formats
# =========================================================================


class TestSignedByLengths:
    """Validate signed_by values fit within String(32)."""

    def test_legacy_hex_prefix_is_16_chars(self, tmp_path):
        """Without keyring, signed_by is the 16-char hex prefix."""
        seal = Seal(key_path=tmp_path / "key")
        capsule = Capsule()
        seal.seal(capsule)

        assert len(capsule.signed_by) == 16
        assert len(capsule.signed_by) <= 32

    def test_keyring_fingerprint_is_11_chars(self, tmp_path):
        """With keyring, signed_by is qp_key_XXXX (11 chars)."""
        key_dir = tmp_path / "keys"
        seal = Seal(
            key_path=key_dir / "key",
            keyring=Keyring(
                keyring_path=key_dir / "keyring.json",
                key_path=key_dir / "key",
            ),
        )
        capsule = Capsule()
        seal.seal(capsule)

        assert capsule.signed_by.startswith("qp_key_")
        assert len(capsule.signed_by) == 11
        assert len(capsule.signed_by) <= 32


# =========================================================================
# SQLite roundtrip — store and retrieve
# =========================================================================


class TestSQLiteSignedAtRoundtrip:
    """signed_at/signed_by survive store → get via CapsuleStorage."""

    @pytest.mark.asyncio
    async def test_signed_at_preserved_on_get(self, tmp_path):
        storage = CapsuleStorage(db_path=tmp_path / "test.db")
        seal = Seal(key_path=tmp_path / "key")

        capsule = Capsule()
        seal.seal(capsule)
        original_at = capsule.signed_at

        await storage.store(capsule)
        retrieved = await storage.get(str(capsule.id))

        assert retrieved is not None
        assert retrieved.signed_at == original_at
        assert retrieved.signed_at.isoformat() == original_at.isoformat()
        await storage.close()

    @pytest.mark.asyncio
    async def test_signed_by_preserved_on_get(self, tmp_path):
        storage = CapsuleStorage(db_path=tmp_path / "test.db")
        seal = Seal(key_path=tmp_path / "key")

        capsule = Capsule()
        seal.seal(capsule)
        original_by = capsule.signed_by

        await storage.store(capsule)
        retrieved = await storage.get(str(capsule.id))

        assert retrieved is not None
        assert retrieved.signed_by == original_by
        await storage.close()

    @pytest.mark.asyncio
    async def test_signed_at_preserved_on_list(self, tmp_path):
        storage = CapsuleStorage(db_path=tmp_path / "test.db")
        seal = Seal(key_path=tmp_path / "key")

        capsule = Capsule()
        seal.seal(capsule)
        original_at = capsule.signed_at

        await storage.store(capsule)
        results = await storage.list()

        assert len(results) == 1
        assert results[0].signed_at == original_at
        await storage.close()

    @pytest.mark.asyncio
    async def test_signed_at_preserved_on_get_latest(self, tmp_path):
        storage = CapsuleStorage(db_path=tmp_path / "test.db")
        seal = Seal(key_path=tmp_path / "key")

        capsule = Capsule()
        seal.seal(capsule)
        original_at = capsule.signed_at

        await storage.store(capsule)
        latest = await storage.get_latest()

        assert latest is not None
        assert latest.signed_at == original_at
        await storage.close()


# =========================================================================
# PostgresCapsuleStorage roundtrip (SQLite-backed for tests)
# =========================================================================


@pytest.fixture
async def pg_storage(tmp_path):
    """PostgresCapsuleStorage backed by SQLite for testing."""
    db_url = f"sqlite+aiosqlite:///{tmp_path / 'test.db'}"
    s = PostgresCapsuleStorage.__new__(PostgresCapsuleStorage)
    s.database_url = db_url
    s._engine = create_async_engine(db_url, echo=False)
    s._session_factory = async_sessionmaker(
        s._engine, class_=AsyncSession, expire_on_commit=False
    )
    s._initialized = False
    yield s
    await s.close()


class TestPGSignedAtRoundtrip:
    """signed_at/signed_by survive store → get via PostgresCapsuleStorage."""

    @pytest.mark.asyncio
    async def test_signed_at_preserved_on_get(self, tmp_path, pg_storage):
        seal = Seal(key_path=tmp_path / "key")
        capsule = Capsule()
        seal.seal(capsule)
        original_at = capsule.signed_at

        await pg_storage.store(capsule)
        retrieved = await pg_storage.get(str(capsule.id))

        assert retrieved is not None
        assert retrieved.signed_at == original_at
        assert retrieved.signed_at.isoformat() == original_at.isoformat()

    @pytest.mark.asyncio
    async def test_signed_by_legacy_hex_preserved(self, tmp_path, pg_storage):
        seal = Seal(key_path=tmp_path / "key")
        capsule = Capsule()
        seal.seal(capsule)

        assert len(capsule.signed_by) == 16
        await pg_storage.store(capsule)
        retrieved = await pg_storage.get(str(capsule.id))

        assert retrieved is not None
        assert retrieved.signed_by == capsule.signed_by

    @pytest.mark.asyncio
    async def test_signed_by_keyring_format_preserved(self, tmp_path, pg_storage):
        key_dir = tmp_path / "keys"
        seal = Seal(
            key_path=key_dir / "key",
            keyring=Keyring(
                keyring_path=key_dir / "keyring.json",
                key_path=key_dir / "key",
            ),
        )
        capsule = Capsule()
        seal.seal(capsule)

        assert capsule.signed_by.startswith("qp_key_")
        await pg_storage.store(capsule)
        retrieved = await pg_storage.get(str(capsule.id))

        assert retrieved is not None
        assert retrieved.signed_by == capsule.signed_by

    @pytest.mark.asyncio
    async def test_signed_at_preserved_on_list(self, tmp_path, pg_storage):
        seal = Seal(key_path=tmp_path / "key")
        capsule = Capsule()
        seal.seal(capsule)
        original_at = capsule.signed_at

        await pg_storage.store(capsule)
        results = await pg_storage.list()

        assert len(results) == 1
        assert results[0].signed_at == original_at

    @pytest.mark.asyncio
    async def test_signed_at_preserved_on_get_latest(self, tmp_path, pg_storage):
        seal = Seal(key_path=tmp_path / "key")
        capsule = Capsule()
        seal.seal(capsule)
        original_at = capsule.signed_at

        await pg_storage.store(capsule)
        latest = await pg_storage.get_latest()

        assert latest is not None
        assert latest.signed_at == original_at

    @pytest.mark.asyncio
    async def test_signed_at_preserved_on_get_all_ordered(self, tmp_path, pg_storage):
        seal = Seal(key_path=tmp_path / "key")

        originals = []
        for seq in range(3):
            c = Capsule()
            c.sequence = seq
            seal.seal(c)
            originals.append(c)
            await pg_storage.store(c)

        ordered = await pg_storage.get_all_ordered()
        assert len(ordered) == 3
        for original, restored in zip(originals, ordered):
            assert restored.signed_at == original.signed_at
            assert restored.signed_by == original.signed_by

    @pytest.mark.asyncio
    async def test_verify_after_roundtrip(self, tmp_path, pg_storage):
        """Capsule still verifies after store+retrieve (seal integrity)."""
        seal = Seal(key_path=tmp_path / "key")
        capsule = Capsule()
        seal.seal(capsule)

        await pg_storage.store(capsule)
        retrieved = await pg_storage.get(str(capsule.id))

        assert retrieved is not None
        assert seal.verify(retrieved) is True
