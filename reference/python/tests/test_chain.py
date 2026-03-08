"""
Tests for hash chain management.

Tests chain integrity and verification.
"""

import json
import tempfile
from pathlib import Path

import pytest
from sqlalchemy import select

from qp_capsule.capsule import Capsule, TriggerSection
from qp_capsule.chain import CapsuleChain
from qp_capsule.seal import Seal
from qp_capsule.storage import CapsuleModel, CapsuleStorage


async def _tamper_stored_capsule(
    storage: CapsuleStorage, sequence: int, field: str, value: str
) -> None:
    """Tamper with a capsule's serialized data in the database without updating its hash."""
    await storage._ensure_db()
    factory = storage._get_session_factory()
    async with factory() as session:
        result = await session.execute(
            select(CapsuleModel).where(CapsuleModel.sequence == sequence)
        )
        model = result.scalar_one()
        data = json.loads(model.data)
        section, key = field.split(".", 1)
        data[section][key] = value
        model.data = json.dumps(data)
        await session.commit()


@pytest.fixture
def temp_db_path():
    """Provide a temporary database path."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir) / "test_capsules.db"


@pytest.fixture
def temp_key_path():
    """Provide a temporary key path."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir) / "test_key"


@pytest.fixture
async def storage(temp_db_path):
    """Provide a storage instance. Closes on teardown."""
    s = CapsuleStorage(db_path=temp_db_path)
    yield s
    await s.close()


@pytest.fixture
def seal(temp_key_path):
    """Provide a seal instance."""
    return Seal(key_path=temp_key_path)


@pytest.fixture
def chain(storage):
    """Provide a chain instance."""
    return CapsuleChain(storage=storage)


def create_capsule(request: str = "test") -> Capsule:
    """Helper to create test Capsules."""
    return Capsule(
        trigger=TriggerSection(
            type="test",
            source="test",
            request=request,
        )
    )


class TestChainAdd:
    """Test adding Capsules to chain."""

    @pytest.mark.asyncio
    async def test_first_capsule_is_genesis(self, chain, seal, storage):
        """First Capsule has sequence 0 and no previous_hash."""
        capsule = create_capsule("first")

        capsule = await chain.add(capsule)

        assert capsule.sequence == 0
        assert capsule.previous_hash is None

    @pytest.mark.asyncio
    async def test_second_capsule_links_to_first(self, chain, seal, storage):
        """Second Capsule links to first."""
        # Add first Capsule
        capsule1 = create_capsule("first")
        capsule1 = await chain.add(capsule1)
        seal.seal(capsule1)
        await storage.store(capsule1)

        # Add second Capsule
        capsule2 = create_capsule("second")
        capsule2 = await chain.add(capsule2)

        assert capsule2.sequence == 1
        assert capsule2.previous_hash == capsule1.hash

    @pytest.mark.asyncio
    async def test_chain_builds_correctly(self, chain, seal, storage):
        """Chain of multiple Capsules builds correctly."""
        capsules = []

        for i in range(5):
            capsule = create_capsule(f"capsule_{i}")
            capsule = await chain.add(capsule)
            seal.seal(capsule)
            await storage.store(capsule)
            capsules.append(capsule)

        # Check sequence
        for i, capsule in enumerate(capsules):
            assert capsule.sequence == i

        # Check linking
        for i in range(1, len(capsules)):
            assert capsules[i].previous_hash == capsules[i - 1].hash


class TestChainVerification:
    """Test chain verification."""

    @pytest.mark.asyncio
    async def test_empty_chain_is_valid(self, chain):
        """Empty chain is valid."""
        result = await chain.verify()

        assert result.valid is True
        assert result.capsules_verified == 0

    @pytest.mark.asyncio
    async def test_single_capsule_chain_is_valid(self, chain, seal, storage):
        """Chain with one Capsule is valid."""
        capsule = create_capsule()
        capsule = await chain.add(capsule)
        seal.seal(capsule)
        await storage.store(capsule)

        result = await chain.verify()

        assert result.valid is True
        assert result.capsules_verified == 1

    @pytest.mark.asyncio
    async def test_valid_chain_verifies(self, chain, seal, storage):
        """Valid chain passes verification."""
        for i in range(5):
            capsule = create_capsule(f"capsule_{i}")
            capsule = await chain.add(capsule)
            seal.seal(capsule)
            await storage.store(capsule)

        result = await chain.verify()

        assert result.valid is True
        assert result.capsules_verified == 5

    @pytest.mark.asyncio
    async def test_genesis_with_previous_hash_fails(self, chain, seal, storage):
        """Genesis Capsule with previous_hash fails verification."""
        capsule = create_capsule()
        capsule.sequence = 0
        capsule.previous_hash = "should_be_none"  # Invalid!
        seal.seal(capsule)
        await storage.store(capsule)

        result = await chain.verify()

        assert result.valid is False
        assert "Genesis" in result.error

    @pytest.mark.asyncio
    async def test_sequence_gap_fails(self, chain, seal, storage):
        """Gap in sequence numbers fails verification."""
        # Create Capsule with sequence 0
        capsule1 = create_capsule("first")
        capsule1.sequence = 0
        capsule1.previous_hash = None
        seal.seal(capsule1)
        await storage.store(capsule1)

        # Create Capsule with sequence 2 (skipping 1)
        capsule2 = create_capsule("second")
        capsule2.sequence = 2  # Gap!
        capsule2.previous_hash = capsule1.hash
        seal.seal(capsule2)
        await storage.store(capsule2)

        result = await chain.verify()

        assert result.valid is False
        assert "gap" in result.error.lower() or "Sequence" in result.error


class TestChainCryptographicVerification:
    """Test chain verification with content hash recomputation and signature checks."""

    @pytest.mark.asyncio
    async def test_verify_content_passes_for_valid_chain(self, chain, seal, storage):
        """verify_content=True passes when content matches stored hashes."""
        for i in range(3):
            capsule = create_capsule(f"capsule_{i}")
            capsule = await chain.add(capsule)
            seal.seal(capsule)
            await storage.store(capsule)

        result = await chain.verify(verify_content=True)

        assert result.valid is True
        assert result.capsules_verified == 3

    @pytest.mark.asyncio
    async def test_verify_content_detects_tampered_content(self, chain, seal, storage):
        """verify_content=True catches content modified after sealing."""
        capsule = create_capsule("original")
        capsule = await chain.add(capsule)
        seal.seal(capsule)
        await storage.store(capsule)

        await _tamper_stored_capsule(storage, sequence=0, field="trigger.request", value="tampered")

        result = await chain.verify(verify_content=True)

        assert result.valid is False
        assert "hash mismatch" in result.error.lower()

    @pytest.mark.asyncio
    async def test_verify_with_seal_passes_for_valid_chain(self, chain, seal, storage):
        """Passing seal= verifies signatures on each capsule."""
        for i in range(3):
            capsule = create_capsule(f"capsule_{i}")
            capsule = await chain.add(capsule)
            seal.seal(capsule)
            await storage.store(capsule)

        result = await chain.verify(seal=seal)

        assert result.valid is True
        assert result.capsules_verified == 3

    @pytest.mark.asyncio
    async def test_verify_with_seal_detects_bad_signature(self, chain, seal, storage):
        """Passing seal= catches forged signatures."""
        capsule = create_capsule("test")
        capsule = await chain.add(capsule)
        seal.seal(capsule)
        capsule.signature = "00" * 64
        await storage.store(capsule)

        result = await chain.verify(seal=seal)

        assert result.valid is False
        assert "Signature verification failed" in result.error

    @pytest.mark.asyncio
    async def test_structural_only_misses_content_tampering(self, chain, seal, storage):
        """Default (structural-only) verification does NOT catch content tampering."""
        capsule = create_capsule("original")
        capsule = await chain.add(capsule)
        seal.seal(capsule)
        await storage.store(capsule)

        await _tamper_stored_capsule(storage, sequence=0, field="trigger.request", value="tampered")

        result = await chain.verify()

        assert result.valid is True, (
            "Structural verification should not catch content tampering "
            "(this is why verify_content=True exists)"
        )

    @pytest.mark.asyncio
    async def test_seal_implies_verify_content(self, chain, seal, storage):
        """Passing seal= implies verify_content=True."""
        capsule = create_capsule("original")
        capsule = await chain.add(capsule)
        seal.seal(capsule)
        await storage.store(capsule)

        await _tamper_stored_capsule(storage, sequence=0, field="trigger.request", value="tampered")

        result = await chain.verify(seal=seal)

        assert result.valid is False
        assert "hash mismatch" in result.error.lower()

    @pytest.mark.asyncio
    async def test_empty_chain_with_verify_content(self, chain):
        """Empty chain is valid even with verify_content=True."""
        result = await chain.verify(verify_content=True)

        assert result.valid is True
        assert result.capsules_verified == 0

    @pytest.mark.asyncio
    async def test_single_capsule_with_verify_content(self, chain, seal, storage):
        """Single capsule chain passes cryptographic verification."""
        capsule = create_capsule("solo")
        capsule = await chain.add(capsule)
        seal.seal(capsule)
        await storage.store(capsule)

        result = await chain.verify(verify_content=True)

        assert result.valid is True
        assert result.capsules_verified == 1

    @pytest.mark.asyncio
    async def test_tamper_in_middle_of_chain(self, chain, seal, storage):
        """Tampering in the middle of the chain is caught by verify_content."""
        for i in range(5):
            capsule = create_capsule(f"capsule_{i}")
            capsule = await chain.add(capsule)
            seal.seal(capsule)
            await storage.store(capsule)

        await _tamper_stored_capsule(
            storage, sequence=2, field="trigger.request", value="tampered_middle"
        )

        result = await chain.verify(verify_content=True)

        assert result.valid is False
        assert result.capsules_verified == 2
        assert "hash mismatch" in result.error.lower()

    @pytest.mark.asyncio
    async def test_default_verify_is_backward_compatible(self, chain, seal, storage):
        """Default verify() with no new params behaves identically to original."""
        for i in range(3):
            capsule = create_capsule(f"capsule_{i}")
            capsule = await chain.add(capsule)
            seal.seal(capsule)
            await storage.store(capsule)

        result = await chain.verify()

        assert result.valid is True
        assert result.capsules_verified == 3
        assert result.error is None
        assert result.broken_at is None

    @pytest.mark.asyncio
    async def test_verify_content_reports_correct_broken_at(self, chain, seal, storage):
        """verify_content reports the ID of the tampered capsule."""
        for i in range(3):
            capsule = create_capsule(f"capsule_{i}")
            capsule = await chain.add(capsule)
            seal.seal(capsule)
            await storage.store(capsule)

        all_capsules = await storage.get_all_ordered()
        tampered_id = str(all_capsules[1].id)
        await _tamper_stored_capsule(storage, sequence=1, field="trigger.request", value="tampered")

        result = await chain.verify(verify_content=True)

        assert result.valid is False
        assert result.broken_at == tampered_id

    @pytest.mark.asyncio
    async def test_verify_content_false_is_structural_only(self, chain, seal, storage):
        """Explicitly passing verify_content=False skips hash recomputation."""
        capsule = create_capsule("original")
        capsule = await chain.add(capsule)
        seal.seal(capsule)
        await storage.store(capsule)

        await _tamper_stored_capsule(storage, sequence=0, field="trigger.request", value="tampered")

        result = await chain.verify(verify_content=False)

        assert result.valid is True


class TestChainOperations:
    """Test chain utility operations."""

    @pytest.mark.asyncio
    async def test_get_chain_length_empty(self, chain):
        """Empty chain has length 0."""
        length = await chain.get_chain_length()
        assert length == 0

    @pytest.mark.asyncio
    async def test_get_chain_length_with_capsules(self, chain, seal, storage):
        """Chain length matches number of Capsules."""
        for i in range(3):
            capsule = create_capsule(f"capsule_{i}")
            capsule = await chain.add(capsule)
            seal.seal(capsule)
            await storage.store(capsule)

        length = await chain.get_chain_length()
        assert length == 3

    @pytest.mark.asyncio
    async def test_get_chain_head(self, chain, seal, storage):
        """get_chain_head returns latest Capsule."""
        for i in range(3):
            capsule = create_capsule(f"capsule_{i}")
            capsule = await chain.add(capsule)
            seal.seal(capsule)
            await storage.store(capsule)

        head = await chain.get_chain_head()

        assert head is not None
        assert head.sequence == 2
        assert head.trigger.request == "capsule_2"

    @pytest.mark.asyncio
    async def test_get_chain_head_empty(self, chain):
        """get_chain_head returns None for empty chain."""
        head = await chain.get_chain_head()
        assert head is None


class TestSQLiteInterfaceCompatibility:
    """Verify SQLite CapsuleStorage accepts tenant_id without error.

    The CapsuleChain passes tenant_id= to storage methods. The SQLite
    backend must accept (and ignore) this kwarg for interface parity
    with PostgresCapsuleStorage.
    """

    @pytest.mark.asyncio
    async def test_store_accepts_tenant_id(self, storage, seal):
        """store(capsule, tenant_id=...) doesn't raise on SQLite."""
        capsule = create_capsule("tenant-compat")
        capsule.sequence = 0
        capsule.previous_hash = None
        seal.seal(capsule)

        stored = await storage.store(capsule, tenant_id="ignored-tenant")
        assert stored.id == capsule.id

    @pytest.mark.asyncio
    async def test_get_latest_accepts_tenant_id(self, storage, seal):
        """get_latest(tenant_id=...) doesn't raise on SQLite."""
        capsule = create_capsule()
        capsule.sequence = 0
        capsule.previous_hash = None
        seal.seal(capsule)
        await storage.store(capsule)

        latest = await storage.get_latest(tenant_id="ignored-tenant")
        assert latest is not None
        assert latest.id == capsule.id

    @pytest.mark.asyncio
    async def test_list_accepts_tenant_id(self, storage, seal):
        """list(tenant_id=...) doesn't raise on SQLite."""
        capsule = create_capsule()
        capsule.sequence = 0
        capsule.previous_hash = None
        seal.seal(capsule)
        await storage.store(capsule)

        results = await storage.list(limit=10, tenant_id="ignored-tenant")
        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_count_accepts_tenant_id(self, storage, seal):
        """count(tenant_id=...) doesn't raise on SQLite."""
        capsule = create_capsule()
        capsule.sequence = 0
        capsule.previous_hash = None
        seal.seal(capsule)
        await storage.store(capsule)

        total = await storage.count(tenant_id="ignored-tenant")
        assert total == 1

    @pytest.mark.asyncio
    async def test_tenant_id_ignored_by_list(self, storage, seal):
        """Different tenant_id values return the same results (no filtering)."""
        for i in range(3):
            c = create_capsule(f"cap-{i}")
            c.sequence = i
            c.previous_hash = None
            seal.seal(c)
            await storage.store(c)

        all_results = await storage.list()
        tenant_a = await storage.list(tenant_id="tenant-a")
        tenant_b = await storage.list(tenant_id="tenant-b")

        assert len(all_results) == len(tenant_a) == len(tenant_b) == 3

    @pytest.mark.asyncio
    async def test_chain_verify_with_tenant_on_sqlite(self, chain, seal, storage):
        """chain.verify(tenant_id=...) works with SQLite backend.

        This is the exact call path that previously raised TypeError.
        """
        for i in range(3):
            c = create_capsule(f"cap-{i}")
            c = await chain.add(c)
            seal.seal(c)
            await storage.store(c)

        result = await chain.verify(tenant_id="any-tenant")
        assert result.valid is True
        assert result.capsules_verified == 3

    @pytest.mark.asyncio
    async def test_chain_add_with_tenant_on_sqlite(self, chain, seal, storage):
        """chain.add(capsule, tenant_id=...) works with SQLite backend."""
        c1 = create_capsule("first")
        c1 = await chain.add(c1, tenant_id="t1")
        assert c1.sequence == 0

        seal.seal(c1)
        await storage.store(c1, tenant_id="t1")

        c2 = create_capsule("second")
        c2 = await chain.add(c2, tenant_id="t1")
        assert c2.sequence == 1
        assert c2.previous_hash == c1.hash

    @pytest.mark.asyncio
    async def test_chain_seal_and_store_with_tenant_on_sqlite(self, chain, seal, storage):
        """chain.seal_and_store(tenant_id=...) works with SQLite backend."""
        c = create_capsule("convenience")
        stored = await chain.seal_and_store(c, seal=seal, tenant_id="t1")

        assert stored.is_sealed()
        assert stored.sequence == 0

        retrieved = await storage.get(str(stored.id))
        assert retrieved is not None
