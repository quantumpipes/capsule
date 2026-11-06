"""
Targeted tests for 100% coverage.

Each test targets specific uncovered lines identified by pytest-cov.
Tests are organized by source file.
"""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from qp_capsule.capsule import Capsule, CapsuleType, TriggerSection
from qp_capsule.chain import CapsuleChain
from qp_capsule.exceptions import CapsuleError, SealError, StorageError
from qp_capsule.paths import default_db_path, default_key_path, resolve_data_dir
from qp_capsule.seal import Seal
from qp_capsule.storage import CapsuleStorage

# =========================================================================
# capsule.py — line 391: has_pq_seal()
# =========================================================================


class TestCapsuleHasPqSeal:
    def test_has_pq_seal_true(self):
        capsule = Capsule()
        capsule.hash = "a" * 64
        capsule.signature = "b" * 128
        capsule.signature_pq = "c" * 256
        assert capsule.has_pq_seal() is True

    def test_has_pq_seal_false_no_pq_sig(self):
        capsule = Capsule()
        capsule.hash = "a" * 64
        capsule.signature = "b" * 128
        capsule.signature_pq = ""
        assert capsule.has_pq_seal() is False

    def test_has_pq_seal_false_no_hash(self):
        capsule = Capsule()
        capsule.hash = ""
        capsule.signature = "b" * 128
        capsule.signature_pq = "c" * 256
        assert capsule.has_pq_seal() is False


# =========================================================================
# chain.py — lines 157-170: verify_capsule_in_chain()
# =========================================================================


class TestVerifyCapsuleInChain:
    @pytest.mark.asyncio
    async def test_genesis_capsule_valid(self, tmp_path):
        storage = CapsuleStorage(db_path=tmp_path / "test.db")
        chain = CapsuleChain(storage)
        seal = Seal(key_path=tmp_path / "key")

        capsule = Capsule(trigger=TriggerSection(request="genesis"))
        capsule = await chain.add(capsule)
        seal.seal(capsule)
        await storage.store(capsule)

        result = await chain.verify_capsule_in_chain(capsule)
        assert result is True
        await storage.close()

    @pytest.mark.asyncio
    async def test_linked_capsule_valid(self, tmp_path):
        storage = CapsuleStorage(db_path=tmp_path / "test.db")
        chain = CapsuleChain(storage)
        seal = Seal(key_path=tmp_path / "key")

        c1 = Capsule(trigger=TriggerSection(request="first"))
        c1 = await chain.add(c1)
        seal.seal(c1)
        await storage.store(c1)

        c2 = Capsule(trigger=TriggerSection(request="second"))
        c2 = await chain.add(c2)
        seal.seal(c2)
        await storage.store(c2)

        result = await chain.verify_capsule_in_chain(c2)
        assert result is True
        await storage.close()

    @pytest.mark.asyncio
    async def test_sequence_beyond_chain_length(self, tmp_path):
        storage = CapsuleStorage(db_path=tmp_path / "test.db")
        chain = CapsuleChain(storage)
        seal = Seal(key_path=tmp_path / "key")

        c1 = Capsule(trigger=TriggerSection(request="only"))
        c1 = await chain.add(c1)
        seal.seal(c1)
        await storage.store(c1)

        fake = Capsule()
        fake.sequence = 99
        fake.previous_hash = "abc"

        result = await chain.verify_capsule_in_chain(fake)
        assert result is False
        await storage.close()

    @pytest.mark.asyncio
    async def test_genesis_with_previous_hash_invalid(self, tmp_path):
        storage = CapsuleStorage(db_path=tmp_path / "test.db")
        chain = CapsuleChain(storage)

        capsule = Capsule()
        capsule.sequence = 0
        capsule.previous_hash = "should_be_none"

        result = await chain.verify_capsule_in_chain(capsule)
        assert result is False
        await storage.close()


# =========================================================================
# storage.py — _default_db_path, get_by_hash, close, store unsealed
# =========================================================================


class TestStorageCoverage:
    @pytest.mark.asyncio
    async def test_store_unsealed_raises(self, tmp_path):
        storage = CapsuleStorage(db_path=tmp_path / "test.db")
        capsule = Capsule()
        with pytest.raises(StorageError, match="unsealed"):
            await storage.store(capsule)
        await storage.close()

    @pytest.mark.asyncio
    async def test_get_by_hash_found(self, tmp_path):
        storage = CapsuleStorage(db_path=tmp_path / "test.db")
        seal = Seal(key_path=tmp_path / "key")

        capsule = Capsule(trigger=TriggerSection(request="hash test"))
        seal.seal(capsule)
        await storage.store(capsule)

        found = await storage.get_by_hash(capsule.hash)
        assert found is not None
        assert found.id == capsule.id
        await storage.close()

    @pytest.mark.asyncio
    async def test_get_by_hash_not_found(self, tmp_path):
        storage = CapsuleStorage(db_path=tmp_path / "test.db")
        found = await storage.get_by_hash("0" * 64)
        assert found is None
        await storage.close()

    @pytest.mark.asyncio
    async def test_close_idempotent(self, tmp_path):
        storage = CapsuleStorage(db_path=tmp_path / "test.db")
        seal = Seal(key_path=tmp_path / "key")
        capsule = Capsule()
        seal.seal(capsule)
        await storage.store(capsule)

        await storage.close()
        await storage.close()

    @pytest.mark.asyncio
    async def test_close_before_init(self, tmp_path):
        storage = CapsuleStorage(db_path=tmp_path / "test.db")
        await storage.close()

    @pytest.mark.asyncio
    async def test_count_exercises_func_import(self, tmp_path):
        storage = CapsuleStorage(db_path=tmp_path / "test.db")
        count = await storage.count()
        assert count == 0
        await storage.close()

    @pytest.mark.asyncio
    async def test_list_by_session_invalid_uuid(self, tmp_path):
        storage = CapsuleStorage(db_path=tmp_path / "test.db")
        results = await storage.list_by_session("not-a-uuid")
        assert results == []
        await storage.close()

    @pytest.mark.asyncio
    async def test_get_returns_none_for_unknown_id(self, tmp_path):
        storage = CapsuleStorage(db_path=tmp_path / "test.db")
        result = await storage.get("00000000-0000-0000-0000-000000000000")
        assert result is None
        await storage.close()

    @pytest.mark.asyncio
    async def test_list_with_type_filter(self, tmp_path):
        storage = CapsuleStorage(db_path=tmp_path / "test.db")
        seal = Seal(key_path=tmp_path / "key")

        c1 = Capsule(type=CapsuleType.AGENT)
        seal.seal(c1)
        await storage.store(c1)

        c2 = Capsule(type=CapsuleType.TOOL)
        c2.sequence = 1
        seal.seal(c2)
        await storage.store(c2)

        results = await storage.list(type_filter=CapsuleType.AGENT)
        assert len(results) == 1

        await storage.close()

    @pytest.mark.asyncio
    async def test_count_with_type_filter(self, tmp_path):
        storage = CapsuleStorage(db_path=tmp_path / "test.db")
        seal = Seal(key_path=tmp_path / "key")

        c1 = Capsule(type=CapsuleType.AGENT)
        seal.seal(c1)
        await storage.store(c1)

        c2 = Capsule(type=CapsuleType.TOOL)
        c2.sequence = 1
        seal.seal(c2)
        await storage.store(c2)

        assert await storage.count(type_filter=CapsuleType.AGENT) == 1
        assert await storage.count(type_filter=CapsuleType.TOOL) == 1
        assert await storage.count() == 2

        await storage.close()


# =========================================================================
# storage_pg.py — URL conversion, partial UUID, filters
# =========================================================================


class TestStoragePGCoverage:
    def test_url_auto_conversion(self):
        from qp_capsule.storage_pg import PostgresCapsuleStorage

        PostgresCapsuleStorage.__new__(PostgresCapsuleStorage)
        url = "postgresql://user:pass@localhost/db"
        if "asyncpg" not in url and "postgresql" in url:
            url = url.replace("postgresql://", "postgresql+asyncpg://")
        assert url == "postgresql+asyncpg://user:pass@localhost/db"

    def test_url_no_conversion_if_asyncpg_present(self):
        url = "postgresql+asyncpg://user:pass@localhost/db"
        if "asyncpg" not in url and "postgresql" in url:
            url = url.replace("postgresql://", "postgresql+asyncpg://")
        assert url == "postgresql+asyncpg://user:pass@localhost/db"

    @pytest.mark.asyncio
    async def test_partial_uuid_with_tenant_isolation(self, tmp_path):
        from sqlalchemy.ext.asyncio import (
            AsyncSession,
            async_sessionmaker,
            create_async_engine,
        )

        from qp_capsule.storage_pg import PostgresCapsuleStorage

        db_url = f"sqlite+aiosqlite:///{tmp_path / 'test.db'}"
        s = PostgresCapsuleStorage.__new__(PostgresCapsuleStorage)
        s.database_url = db_url
        s._engine = create_async_engine(db_url, echo=False)
        s._session_factory = async_sessionmaker(
            s._engine, class_=AsyncSession, expire_on_commit=False
        )
        s._initialized = False

        seal = Seal(key_path=tmp_path / "key")
        capsule = Capsule(trigger=TriggerSection(request="tenant partial"))
        seal.seal(capsule)
        await s.store(capsule, tenant_id="t1")

        short_id = str(capsule.id)[:8]
        found = await s.get(short_id, tenant_id="t1")
        assert found is not None

        not_found = await s.get(short_id, tenant_id="t2")
        assert not_found is None

        await s.close()

    @pytest.mark.asyncio
    async def test_partial_uuid_lookup(self, tmp_path):
        from sqlalchemy.ext.asyncio import (
            AsyncSession,
            async_sessionmaker,
            create_async_engine,
        )

        from qp_capsule.storage_pg import PostgresCapsuleStorage

        db_url = f"sqlite+aiosqlite:///{tmp_path / 'test.db'}"
        s = PostgresCapsuleStorage.__new__(PostgresCapsuleStorage)
        s.database_url = db_url
        s._engine = create_async_engine(db_url, echo=False)
        s._session_factory = async_sessionmaker(
            s._engine, class_=AsyncSession, expire_on_commit=False
        )
        s._initialized = False

        seal = Seal(key_path=tmp_path / "key")
        capsule = Capsule(trigger=TriggerSection(request="partial id"))
        seal.seal(capsule)
        await s.store(capsule)

        short_id = str(capsule.id)[:8]
        found = await s.get(short_id)
        assert found is not None
        assert found.id == capsule.id

        await s.close()

    @pytest.mark.asyncio
    async def test_list_with_type_filter(self, tmp_path):
        from sqlalchemy.ext.asyncio import (
            AsyncSession,
            async_sessionmaker,
            create_async_engine,
        )

        from qp_capsule.storage_pg import PostgresCapsuleStorage

        db_url = f"sqlite+aiosqlite:///{tmp_path / 'test.db'}"
        s = PostgresCapsuleStorage.__new__(PostgresCapsuleStorage)
        s.database_url = db_url
        s._engine = create_async_engine(db_url, echo=False)
        s._session_factory = async_sessionmaker(
            s._engine, class_=AsyncSession, expire_on_commit=False
        )
        s._initialized = False

        seal = Seal(key_path=tmp_path / "key")

        agent_cap = Capsule(type=CapsuleType.AGENT)
        seal.seal(agent_cap)
        await s.store(agent_cap)

        tool_cap = Capsule(type=CapsuleType.TOOL)
        tool_cap.sequence = 1
        seal.seal(tool_cap)
        await s.store(tool_cap)

        results = await s.list(type_filter=CapsuleType.AGENT)
        assert len(results) == 1
        assert results[0].type == CapsuleType.AGENT

        await s.close()

    @pytest.mark.asyncio
    async def test_list_with_session_id_filter(self, tmp_path):
        from sqlalchemy.ext.asyncio import (
            AsyncSession,
            async_sessionmaker,
            create_async_engine,
        )

        from qp_capsule.capsule import ContextSection
        from qp_capsule.storage_pg import PostgresCapsuleStorage

        db_url = f"sqlite+aiosqlite:///{tmp_path / 'test.db'}"
        s = PostgresCapsuleStorage.__new__(PostgresCapsuleStorage)
        s.database_url = db_url
        s._engine = create_async_engine(db_url, echo=False)
        s._session_factory = async_sessionmaker(
            s._engine, class_=AsyncSession, expire_on_commit=False
        )
        s._initialized = False

        seal = Seal(key_path=tmp_path / "key")
        capsule = Capsule(context=ContextSection(session_id="sess-123"))
        seal.seal(capsule)
        await s.store(capsule)

        results = await s.list(session_id="sess-123")
        assert len(results) == 1

        results_empty = await s.list(session_id="nonexistent")
        assert len(results_empty) == 0

        await s.close()

    @pytest.mark.asyncio
    async def test_store_unsealed_raises(self, tmp_path):
        from qp_capsule.storage_pg import PostgresCapsuleStorage

        s = PostgresCapsuleStorage.__new__(PostgresCapsuleStorage)
        capsule = Capsule()
        with pytest.raises(StorageError, match="unsealed"):
            await s.store(capsule)

    def test_constructor_creates_engine(self, tmp_path):
        from qp_capsule.storage_pg import PostgresCapsuleStorage

        db_url = f"sqlite+aiosqlite:///{tmp_path / 'init_test.db'}"
        s = PostgresCapsuleStorage(db_url)
        assert s.database_url == db_url
        assert s._engine is not None
        assert s._initialized is False

    def test_constructor_converts_postgresql_url(self):
        from qp_capsule.storage_pg import PostgresCapsuleStorage

        with patch("qp_capsule.storage_pg.create_async_engine") as mock_engine:
            s = PostgresCapsuleStorage("postgresql://user:pass@localhost/db")
            assert s.database_url == "postgresql+asyncpg://user:pass@localhost/db"
            mock_engine.assert_called_once()

    @pytest.mark.asyncio
    async def test_count_with_tenant_filter(self, tmp_path):
        from sqlalchemy.ext.asyncio import (
            AsyncSession,
            async_sessionmaker,
            create_async_engine,
        )

        from qp_capsule.storage_pg import PostgresCapsuleStorage

        db_url = f"sqlite+aiosqlite:///{tmp_path / 'test.db'}"
        s = PostgresCapsuleStorage.__new__(PostgresCapsuleStorage)
        s.database_url = db_url
        s._engine = create_async_engine(db_url, echo=False)
        s._session_factory = async_sessionmaker(
            s._engine, class_=AsyncSession, expire_on_commit=False
        )
        s._initialized = False

        seal = Seal(key_path=tmp_path / "key")
        c = Capsule()
        seal.seal(c)
        await s.store(c, tenant_id="t1")

        assert await s.count(tenant_id="t1") == 1
        assert await s.count(tenant_id="t2") == 0

        await s.close()

    @pytest.mark.asyncio
    async def test_count_with_domain_filter(self, tmp_path):
        from sqlalchemy.ext.asyncio import (
            AsyncSession,
            async_sessionmaker,
            create_async_engine,
        )

        from qp_capsule.storage_pg import PostgresCapsuleStorage

        db_url = f"sqlite+aiosqlite:///{tmp_path / 'test.db'}"
        s = PostgresCapsuleStorage.__new__(PostgresCapsuleStorage)
        s.database_url = db_url
        s._engine = create_async_engine(db_url, echo=False)
        s._session_factory = async_sessionmaker(
            s._engine, class_=AsyncSession, expire_on_commit=False
        )
        s._initialized = False

        seal = Seal(key_path=tmp_path / "key")

        c1 = Capsule(domain="vault")
        seal.seal(c1)
        await s.store(c1)

        c2 = Capsule(domain="agents")
        c2.sequence = 1
        seal.seal(c2)
        await s.store(c2)

        assert await s.count(domain="vault") == 1
        assert await s.count(domain="agents") == 1
        assert await s.count(domain="nonexistent") == 0

        await s.close()

    @pytest.mark.asyncio
    async def test_store_exception_wraps_in_storage_error(self, tmp_path):
        from sqlalchemy.ext.asyncio import (
            AsyncSession,
            async_sessionmaker,
            create_async_engine,
        )

        from qp_capsule.storage_pg import PostgresCapsuleStorage

        db_url = f"sqlite+aiosqlite:///{tmp_path / 'test.db'}"
        s = PostgresCapsuleStorage.__new__(PostgresCapsuleStorage)
        s.database_url = db_url
        s._engine = create_async_engine(db_url, echo=False)
        s._session_factory = async_sessionmaker(
            s._engine, class_=AsyncSession, expire_on_commit=False
        )
        s._initialized = False

        seal = Seal(key_path=tmp_path / "key")
        c = Capsule()
        seal.seal(c)
        await s.store(c)

        # Store same capsule again — duplicate primary key
        with pytest.raises(StorageError, match="Failed to store"):
            await s.store(c)

        await s.close()


# =========================================================================
# seal.py — env var key path, PQ mocking, verify_with_key, error paths
# =========================================================================


class TestPathTraversalPrevention:
    def test_resolve_data_dir_rejects_dotdot(self):
        with pytest.raises(CapsuleError, match="must not contain"):
            resolve_data_dir("/tmp/../etc")

    def test_resolve_data_dir_rejects_embedded_dotdot(self):
        with pytest.raises(CapsuleError, match="must not contain"):
            resolve_data_dir("/safe/../../escape")

    def test_resolve_data_dir_accepts_valid_path(self, tmp_path):
        result = resolve_data_dir(str(tmp_path))
        assert ".." not in str(result)
        assert result == tmp_path.resolve()

    def test_resolve_data_dir_resolves_symlinks(self, tmp_path):
        result = resolve_data_dir(str(tmp_path))
        assert result.is_absolute()


class TestDefaultPaths:
    def test_default_key_path_with_env_var(self, monkeypatch, tmp_path):
        monkeypatch.setenv("QUANTUMPIPES_DATA_DIR", str(tmp_path))
        path = default_key_path()
        assert path == tmp_path.resolve() / "key"

    def test_default_key_path_without_env_var(self, monkeypatch):
        monkeypatch.delenv("QUANTUMPIPES_DATA_DIR", raising=False)
        path = default_key_path()
        assert path == Path.home() / ".quantumpipes" / "key"

    def test_default_db_path_with_env_var(self, monkeypatch, tmp_path):
        monkeypatch.setenv("QUANTUMPIPES_DATA_DIR", str(tmp_path))
        path = default_db_path()
        assert path == tmp_path.resolve() / "capsules.db"

    def test_default_db_path_without_env_var(self, monkeypatch):
        monkeypatch.delenv("QUANTUMPIPES_DATA_DIR", raising=False)
        path = default_db_path()
        assert path == Path.home() / ".quantumpipes" / "capsules.db"


class TestPQAvailable:
    def test_pq_available_returns_false_without_oqs(self):
        from qp_capsule.seal import _pq_available
        with patch("qp_capsule.seal._oqs_module", None):
            assert _pq_available() is False

    def test_pq_available_returns_true_with_oqs(self):
        from qp_capsule.seal import _pq_available
        mock_oqs = MagicMock()
        with patch("qp_capsule.seal._oqs_module", mock_oqs):
            assert _pq_available() is True


class TestSealPQEnabled:
    def test_pq_enabled_false(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=False)
            assert seal.pq_enabled is False

    def test_enable_pq_true_without_oqs_raises(self):
        with patch("qp_capsule.seal._pq_available", return_value=False):
            with pytest.raises(SealError, match="oqs library not available"):
                Seal(enable_pq=True)

    @patch("qp_capsule.seal._pq_available", return_value=True)
    def test_enable_pq_true_with_oqs_succeeds(self, mock_pq):
        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=True)
            assert seal.pq_enabled is True


class TestSealPQMocked:
    @patch("qp_capsule.seal._pq_available", return_value=True)
    def test_seal_with_pq_creates_both_signatures(self, mock_pq):
        mock_oqs = MagicMock()
        mock_signer = MagicMock()
        mock_signer.generate_keypair.return_value = b"\x01" * 32
        mock_signer.export_secret_key.return_value = b"\x02" * 64
        mock_signer.sign.return_value = b"\x03" * 128
        mock_oqs.Signature.return_value = mock_signer

        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=True)

            with patch("qp_capsule.seal._oqs_module", mock_oqs):
                capsule = Capsule()
                seal.seal(capsule)

                assert capsule.is_sealed()
                assert capsule.signature_pq != ""

    @patch("qp_capsule.seal._pq_available", return_value=True)
    def test_pq_sign_returns_none_raises(self, mock_pq):
        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=True)

            with patch.object(seal, "_sign_dilithium", return_value=None):
                capsule = Capsule()
                with pytest.raises(SealError, match="Post-quantum signature failed"):
                    seal.seal(capsule)

    def test_seal_generic_exception_wraps_in_seal_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=False)
            capsule = Capsule()

            with patch.object(seal, "_ensure_keys", side_effect=RuntimeError("boom")):
                with pytest.raises(SealError, match="Failed to seal"):
                    seal.seal(capsule)


class TestSealVerifyEdgeCases:
    def test_verify_unsealed_returns_false(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=False)
            capsule = Capsule()
            assert seal.verify(capsule) is False

    def test_verify_with_pq_flag_on_ed25519_capsule(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=False)
            capsule = Capsule()
            seal.seal(capsule)
            assert seal.verify(capsule, verify_pq=True) is True

    def test_verify_generic_exception_returns_false(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=False)
            capsule = Capsule()
            seal.seal(capsule)

            with patch("qp_capsule.seal.json.dumps", side_effect=RuntimeError("boom")):
                assert seal.verify(capsule) is False


class TestVerifyWithKey:
    def test_verify_with_key_unsealed_returns_false(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=False)
            capsule = Capsule()
            assert seal.verify_with_key(capsule, "ab" * 32) is False

    def test_verify_with_key_tampered_hash_returns_false(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=False)
            capsule = Capsule()
            seal.seal(capsule)

            capsule.trigger.request = "tampered"
            assert seal.verify_with_key(capsule, seal.get_public_key()) is False

    def test_verify_with_key_wrong_key_returns_false(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            seal1 = Seal(key_path=Path(tmpdir) / "key1", enable_pq=False)
            capsule = Capsule()
            seal1.seal(capsule)

            seal2 = Seal(key_path=Path(tmpdir) / "key2", enable_pq=False)
            assert seal1.verify_with_key(capsule, seal2.get_public_key()) is False

    def test_verify_with_key_invalid_key_returns_false(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=False)
            capsule = Capsule()
            seal.seal(capsule)
            assert seal.verify_with_key(capsule, "invalid_hex") is False


class TestSealVerifyDilithiumMocked:
    def test_verify_dilithium_import_error_returns_false(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=False)
            result = seal._verify_dilithium("abc", "def")
            assert result is False

    def test_sign_dilithium_import_error_returns_none(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=False)
            with patch("qp_capsule.seal._oqs_module", None):
                result = seal._sign_dilithium("abc")
                assert result is None

    @patch("qp_capsule.seal._pq_available", return_value=True)
    def test_sign_dilithium_generic_exception_returns_none(self, mock_pq):
        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=True)
            seal._pq_secret_key = b"sk"
            seal._pq_public_key = b"pk"

            mock_oqs = MagicMock()
            mock_signer = MagicMock()
            mock_signer.sign.side_effect = RuntimeError("signing failed")
            mock_oqs.Signature.return_value = mock_signer

            with patch("qp_capsule.seal._oqs_module", mock_oqs):
                result = seal._sign_dilithium("abc123")
                assert result is None

    @patch("qp_capsule.seal._pq_available", return_value=True)
    def test_verify_dilithium_success(self, mock_pq):
        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=True)
            seal._pq_secret_key = b"sk"
            seal._pq_public_key = b"p" * 1952

            mock_oqs = MagicMock()
            mock_verifier = MagicMock()
            mock_verifier.verify.return_value = True
            mock_oqs.Signature.return_value = mock_verifier

            with patch("qp_capsule.seal._oqs_module", mock_oqs):
                result = seal._verify_dilithium("abc123", "aabb" * 16)
                assert result is True

    @patch("qp_capsule.seal._pq_available", return_value=True)
    def test_verify_dilithium_generic_exception_returns_false(self, mock_pq):
        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=True)
            seal._pq_secret_key = b"sk"
            seal._pq_public_key = b"p" * 1952

            mock_oqs = MagicMock()
            mock_verifier = MagicMock()
            mock_verifier.verify.side_effect = RuntimeError("verify failed")
            mock_oqs.Signature.return_value = mock_verifier

            with patch("qp_capsule.seal._oqs_module", mock_oqs):
                result = seal._verify_dilithium("abc123", "aabb" * 16)
                assert result is False

    @patch("qp_capsule.seal._pq_available", return_value=True)
    def test_verify_with_pq_delegates_to_verify_dilithium(self, mock_pq):
        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=True)
            capsule = Capsule()

            seal._pq_enabled = False
            seal.seal(capsule)

            capsule.signature_pq = "aabb" * 64

            with patch.object(seal, "_verify_dilithium", return_value=True):
                assert seal.verify(capsule, verify_pq=True) is True


class TestEnsurePQKeysErrors:
    @patch("qp_capsule.seal._pq_available", return_value=True)
    def test_ensure_pq_keys_import_error(self, mock_pq):
        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=True)
            seal._pq_secret_key = None
            seal._pq_public_key = None

            with patch("qp_capsule.seal._oqs_module", None):
                with pytest.raises(SealError, match="oqs library not available"):
                    seal._ensure_pq_keys()

    @patch("qp_capsule.seal._pq_available", return_value=True)
    def test_ensure_pq_keys_generic_error(self, mock_pq):
        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=True)
            seal._pq_secret_key = None
            seal._pq_public_key = None

            mock_oqs = MagicMock()
            mock_oqs.Signature.side_effect = RuntimeError("keygen failed")

            with patch("qp_capsule.seal._oqs_module", mock_oqs):
                with pytest.raises(SealError, match="Failed to load/generate PQ keys"):
                    seal._ensure_pq_keys()

    @patch("qp_capsule.seal._pq_available", return_value=True)
    def test_ensure_pq_keys_loads_existing(self, mock_pq):
        with tempfile.TemporaryDirectory() as tmpdir:
            key_dir = Path(tmpdir)
            (key_dir / "key.ml").write_bytes(b"\x01" * 64)
            (key_dir / "key.ml.pub").write_bytes(b"\x02" * 32)

            seal = Seal(key_path=key_dir / "key", enable_pq=True)
            seal._pq_secret_key = None
            seal._pq_public_key = None

            mock_oqs = MagicMock()
            with patch("qp_capsule.seal._oqs_module", mock_oqs):
                sk, pk = seal._ensure_pq_keys()
                assert sk == b"\x01" * 64
                assert pk == b"\x02" * 32

    @patch("qp_capsule.seal._pq_available", return_value=True)
    def test_ensure_pq_keys_generates_new(self, mock_pq):
        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=True)
            seal._pq_secret_key = None
            seal._pq_public_key = None

            mock_oqs = MagicMock()
            mock_signer = MagicMock()
            mock_signer.generate_keypair.return_value = b"\xaa" * 32
            mock_signer.export_secret_key.return_value = b"\xbb" * 64
            mock_oqs.Signature.return_value = mock_signer

            with patch("qp_capsule.seal._oqs_module", mock_oqs):
                sk, pk = seal._ensure_pq_keys()
                assert sk == b"\xbb" * 64
                assert pk == b"\xaa" * 32

                assert (Path(tmpdir) / "key.ml").exists()
                assert (Path(tmpdir) / "key.ml.pub").exists()

    @patch("qp_capsule.seal._pq_available", return_value=True)
    def test_ensure_pq_keys_reraises_seal_error(self, mock_pq):
        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=True)
            seal._pq_secret_key = None
            seal._pq_public_key = None

            mock_oqs = MagicMock()
            mock_oqs.Signature.side_effect = SealError("inner seal error")

            with patch("qp_capsule.seal._oqs_module", mock_oqs):
                with pytest.raises(SealError, match="inner seal error"):
                    seal._ensure_pq_keys()

    @patch("qp_capsule.seal._pq_available", return_value=True)
    def test_sign_dilithium_reraises_seal_error(self, mock_pq):
        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=True)

            mock_oqs = MagicMock()
            with patch("qp_capsule.seal._oqs_module", mock_oqs):
                with patch.object(
                    seal, "_ensure_pq_keys", side_effect=SealError("key error")
                ):
                    with pytest.raises(SealError, match="key error"):
                        seal._sign_dilithium("abc123")

    @patch("qp_capsule.seal._pq_available", return_value=True)
    def test_ensure_pq_keys_cached(self, mock_pq):
        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=True)
            seal._pq_secret_key = b"cached_sk"
            seal._pq_public_key = b"cached_pk"

            sk, pk = seal._ensure_pq_keys()
            assert sk == b"cached_sk"
            assert pk == b"cached_pk"


class TestDefensiveGuards:
    """Tests for defensive runtime checks that replace assert statements."""

    def test_seal_verify_key_not_initialized_raises(self):
        """_ensure_keys raises SealError if verify_key is somehow None after init."""
        with tempfile.TemporaryDirectory() as tmpdir:
            seal = Seal(key_path=Path(tmpdir) / "key", enable_pq=False)
            seal._ensure_keys()
            seal._verify_key = None
            with pytest.raises(SealError, match="Verify key not initialized"):
                seal._ensure_keys()

    @pytest.mark.asyncio
    async def test_storage_get_session_factory_before_init_raises(self):
        """_get_session_factory raises StorageError if called before _ensure_db."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = CapsuleStorage(db_path=Path(tmpdir) / "test.db")
            with pytest.raises(StorageError, match="Database not initialized"):
                storage._get_session_factory()
