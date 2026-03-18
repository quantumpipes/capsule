"""
Invariant and property tests for the Capsule protocol.

PRIORITY: These tests verify protocol-level guarantees that, if violated,
would make the entire audit trail worthless. Line coverage doesn't catch
these — you need to test *properties*, not just *paths*.

STRESSOR: Random data, systematic field mutation, and roundtrip verification
stress the system beyond what example-based tests can reach.
"""

import json
import uuid
from datetime import UTC, datetime

import pytest

from qp_capsule import (
    Capsule,
    CapsuleChain,
    CapsuleStorage,
    CapsuleType,
    Seal,
    TriggerSection,
    compute_hash,
)
from qp_capsule.capsule import (
    AuthoritySection,
    ContextSection,
    ExecutionSection,
    OutcomeSection,
    ReasoningOption,
    ReasoningSection,
    ToolCall,
)

FIXED_TIME = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)


def _fully_populated_capsule() -> Capsule:
    return Capsule(
        id=uuid.UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
        type=CapsuleType.AGENT,
        domain="agents",
        parent_id=uuid.UUID("b2c3d4e5-f6a7-8901-bcde-f12345678901"),
        sequence=5,
        previous_hash="a" * 64,
        trigger=TriggerSection(
            type="user_request", source="test", timestamp=FIXED_TIME,
            request="Do the thing", correlation_id="corr-123", user_id="user-1",
        ),
        context=ContextSection(
            agent_id="agent-1", session_id="sess-1",
            environment={"key": "value", "nested": {"deep": True}},
        ),
        reasoning=ReasoningSection(
            analysis="Analyzed the situation",
            options=[
                ReasoningOption(
                    id="opt_0", description="Option A",
                    pros=["Good"], cons=["Bad"],
                    estimated_impact={"scope": "high"},
                    feasibility=0.9, risks=["Risk 1"],
                    selected=True, rejection_reason="",
                ),
                ReasoningOption(
                    id="opt_1", description="Option B",
                    pros=["Fast"], cons=["Risky"],
                    estimated_impact={"scope": "low"},
                    feasibility=0.4, risks=["Risk 2"],
                    selected=False, rejection_reason="Too risky",
                ),
            ],
            selected_option="Option A",
            reasoning="Best tradeoff",
            confidence=0.92,
            model="test-model",
            prompt_hash="b" * 64,
        ),
        authority=AuthoritySection(
            type="human_approved", approver="admin",
            policy_reference="POL-001",
            chain=[{"level": 1, "actor": "admin", "decision": "approved"}],
            escalation_reason="Required human approval",
        ),
        execution=ExecutionSection(
            tool_calls=[
                ToolCall(
                    tool="kubectl", arguments={"cmd": "apply"},
                    result={"ok": True}, success=True,
                    duration_ms=1200, error=None,
                ),
            ],
            duration_ms=1200,
            resources_used={"cpu": 2.5},
        ),
        outcome=OutcomeSection(
            status="success", result={"deployed": True},
            summary="Deployed successfully",
            error=None,
            side_effects=["Updated deployment"],
            metrics={"tokens": 500, "cost": 0.01},
        ),
    )


# =========================================================================
# INVARIANT 1: Serialization roundtrip is lossless
# "If to_dict -> from_dict loses information, the audit trail is unreliable"
# =========================================================================


class TestSerializationRoundtrip:

    def test_minimal_capsule_roundtrips_losslessly(self):
        original = Capsule(trigger=TriggerSection(timestamp=FIXED_TIME))
        restored = Capsule.from_dict(original.to_dict())

        assert original.to_dict() == restored.to_dict(), (
            "Minimal capsule lost data in roundtrip"
        )

    def test_fully_populated_capsule_roundtrips_losslessly(self):
        original = _fully_populated_capsule()
        restored = Capsule.from_dict(original.to_dict())

        assert original.to_dict() == restored.to_dict(), (
            "Fully populated capsule lost data in roundtrip"
        )

    def test_every_capsule_type_roundtrips(self):
        for capsule_type in CapsuleType:
            original = Capsule(
                type=capsule_type,
                trigger=TriggerSection(timestamp=FIXED_TIME),
            )
            restored = Capsule.from_dict(original.to_dict())
            assert original.to_dict() == restored.to_dict(), (
                f"CapsuleType.{capsule_type.name} lost data in roundtrip"
            )

    def test_reasoning_options_survive_roundtrip(self):
        original = _fully_populated_capsule()
        restored = Capsule.from_dict(original.to_dict())

        orig_opts = original.to_dict()["reasoning"]["options"]
        rest_opts = restored.to_dict()["reasoning"]["options"]

        assert len(orig_opts) == len(rest_opts), "Option count changed"
        for i, (o, r) in enumerate(zip(orig_opts, rest_opts)):
            assert o == r, (
                f"ReasoningOption[{i}] differs after roundtrip:\n"
                f"  Original: {o}\n"
                f"  Restored: {r}"
            )

    def test_double_roundtrip_is_idempotent(self):
        original = _fully_populated_capsule()
        once = Capsule.from_dict(original.to_dict())
        twice = Capsule.from_dict(once.to_dict())

        assert once.to_dict() == twice.to_dict(), (
            "Double roundtrip is not idempotent — data drifts on each cycle"
        )


# =========================================================================
# INVARIANT 2: Hashing is deterministic
# "If the same capsule produces different hashes, verification is impossible"
# =========================================================================


class TestHashDeterminism:

    def test_same_capsule_always_produces_same_hash(self):
        capsule = _fully_populated_capsule()
        hashes = {compute_hash(capsule.to_dict()) for _ in range(100)}

        assert len(hashes) == 1, (
            f"Hash is non-deterministic: got {len(hashes)} distinct hashes "
            f"from 100 computations of the same capsule"
        )

    def test_hash_changes_when_any_content_changes(self):
        baseline = _fully_populated_capsule()
        baseline_hash = compute_hash(baseline.to_dict())

        mutations = [
            ("type", CapsuleType.TOOL),
            ("domain", "vault"),
            ("sequence", 99),
        ]

        for field, new_value in mutations:
            mutant = _fully_populated_capsule()
            setattr(mutant, field, new_value)
            mutant_hash = compute_hash(mutant.to_dict())

            assert mutant_hash != baseline_hash, (
                f"Changing '{field}' did NOT change the hash. "
                f"Content tampering would be undetectable."
            )

    def test_hash_changes_when_trigger_request_changes(self):
        c1 = _fully_populated_capsule()
        c2 = _fully_populated_capsule()
        c2.trigger.request = "Different request"

        assert compute_hash(c1.to_dict()) != compute_hash(c2.to_dict()), (
            "Changing trigger.request did not change the hash"
        )

    def test_hash_changes_when_reasoning_confidence_changes(self):
        c1 = _fully_populated_capsule()
        c2 = _fully_populated_capsule()
        c2.reasoning.confidence = 0.01

        assert compute_hash(c1.to_dict()) != compute_hash(c2.to_dict()), (
            "Changing reasoning.confidence did not change the hash"
        )

    def test_hash_changes_when_outcome_status_changes(self):
        c1 = _fully_populated_capsule()
        c2 = _fully_populated_capsule()
        c2.outcome.status = "failure"

        assert compute_hash(c1.to_dict()) != compute_hash(c2.to_dict()), (
            "Changing outcome.status did not change the hash"
        )

    def test_canonical_json_key_order_is_deterministic(self):
        capsule = _fully_populated_capsule()
        d = capsule.to_dict()

        results = set()
        for _ in range(50):
            canonical = json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            results.add(canonical)

        assert len(results) == 1, (
            "Canonical JSON is non-deterministic across serializations"
        )


# =========================================================================
# INVARIANT 3: Sealing is tamper-evident for ALL content fields
# "If ANY field can be modified without detection, the seal is broken"
# =========================================================================


class TestTamperEvidence:

    @pytest.fixture
    def sealed_capsule(self, tmp_path):
        seal = Seal(key_path=tmp_path / "key", enable_pq=False)
        capsule = _fully_populated_capsule()
        seal.seal(capsule)
        return capsule, seal

    def test_tamper_trigger_source(self, sealed_capsule):
        capsule, seal = sealed_capsule
        capsule.trigger.source = "TAMPERED"
        assert seal.verify(capsule) is False

    def test_tamper_trigger_request(self, sealed_capsule):
        capsule, seal = sealed_capsule
        capsule.trigger.request = "TAMPERED"
        assert seal.verify(capsule) is False

    def test_tamper_context_agent_id(self, sealed_capsule):
        capsule, seal = sealed_capsule
        capsule.context.agent_id = "TAMPERED"
        assert seal.verify(capsule) is False

    def test_tamper_reasoning_confidence(self, sealed_capsule):
        capsule, seal = sealed_capsule
        capsule.reasoning.confidence = 0.01
        assert seal.verify(capsule) is False

    def test_tamper_reasoning_selected_option(self, sealed_capsule):
        capsule, seal = sealed_capsule
        capsule.reasoning.selected_option = "TAMPERED"
        assert seal.verify(capsule) is False

    def test_tamper_authority_type(self, sealed_capsule):
        capsule, seal = sealed_capsule
        capsule.authority.type = "autonomous"
        assert seal.verify(capsule) is False

    def test_tamper_authority_approver(self, sealed_capsule):
        capsule, seal = sealed_capsule
        capsule.authority.approver = "TAMPERED"
        assert seal.verify(capsule) is False

    def test_tamper_execution_duration(self, sealed_capsule):
        capsule, seal = sealed_capsule
        capsule.execution.duration_ms = 999999
        assert seal.verify(capsule) is False

    def test_tamper_outcome_status(self, sealed_capsule):
        capsule, seal = sealed_capsule
        capsule.outcome.status = "failure"
        assert seal.verify(capsule) is False

    def test_tamper_outcome_summary(self, sealed_capsule):
        capsule, seal = sealed_capsule
        capsule.outcome.summary = "TAMPERED"
        assert seal.verify(capsule) is False

    def test_tamper_domain(self, sealed_capsule):
        capsule, seal = sealed_capsule
        capsule.domain = "TAMPERED"
        assert seal.verify(capsule) is False

    def test_tamper_sequence(self, sealed_capsule):
        capsule, seal = sealed_capsule
        capsule.sequence = 999
        assert seal.verify(capsule) is False

    def test_tamper_type(self, sealed_capsule):
        capsule, seal = sealed_capsule
        capsule.type = CapsuleType.KILL
        assert seal.verify(capsule) is False


# =========================================================================
# INVARIANT 4: Chain is append-only and tamper-evident
# "If records can be reordered, deleted, or inserted undetected, the
#  chain provides no integrity guarantee"
# =========================================================================


class TestChainIntegrity:

    @pytest.fixture
    async def chain_with_5(self, tmp_path):
        storage = CapsuleStorage(db_path=tmp_path / "test.db")
        chain = CapsuleChain(storage)
        seal = Seal(key_path=tmp_path / "key", enable_pq=False)

        capsules = []
        for i in range(5):
            c = Capsule(trigger=TriggerSection(
                request=f"Action {i}", timestamp=FIXED_TIME,
            ))
            c = await chain.seal_and_store(c, seal)
            capsules.append(c)

        yield storage, chain, seal, capsules
        await storage.close()

    @pytest.mark.asyncio
    async def test_valid_chain_verifies(self, chain_with_5):
        _, chain, _, _ = chain_with_5
        result = await chain.verify()
        assert result.valid is True
        assert result.capsules_verified == 5

    @pytest.mark.asyncio
    async def test_each_capsule_links_to_previous(self, chain_with_5):
        _, _, _, capsules = chain_with_5

        assert capsules[0].previous_hash is None, "Genesis must have no previous"
        for i in range(1, len(capsules)):
            assert capsules[i].previous_hash == capsules[i - 1].hash, (
                f"Capsule {i} previous_hash doesn't match capsule {i-1} hash"
            )

    @pytest.mark.asyncio
    async def test_sequences_are_consecutive(self, chain_with_5):
        _, _, _, capsules = chain_with_5
        for i, c in enumerate(capsules):
            assert c.sequence == i, (
                f"Capsule {i} has sequence {c.sequence}, expected {i}"
            )

    @pytest.mark.asyncio
    async def test_chain_length_matches_capsule_count(self, chain_with_5):
        _, chain, _, _ = chain_with_5
        length = await chain.get_chain_length()
        assert length == 5

    @pytest.mark.asyncio
    async def test_chain_head_is_last_capsule(self, chain_with_5):
        _, chain, _, capsules = chain_with_5
        head = await chain.get_chain_head()
        assert head is not None
        assert head.id == capsules[-1].id


# =========================================================================
# INVARIANT 5: Protocol contract is satisfied by both backends
# =========================================================================


class TestProtocolContract:

    def test_sqlite_satisfies_protocol(self, tmp_path):
        from qp_capsule import CapsuleStorageProtocol

        storage = CapsuleStorage(db_path=tmp_path / "test.db")
        assert isinstance(storage, CapsuleStorageProtocol), (
            "CapsuleStorage does not satisfy CapsuleStorageProtocol"
        )

    def test_postgres_satisfies_protocol(self):
        from qp_capsule import CapsuleStorageProtocol
        from qp_capsule.storage_pg import PostgresCapsuleStorage

        storage = PostgresCapsuleStorage.__new__(PostgresCapsuleStorage)
        assert isinstance(storage, CapsuleStorageProtocol), (
            "PostgresCapsuleStorage does not satisfy CapsuleStorageProtocol"
        )


# =========================================================================
# BLACK SWAN: Unicode in every field
# "If Unicode breaks hashing or storage, the protocol fails globally"
# =========================================================================


class TestUnicodeResilience:

    UNICODE_STRINGS = [
        "Hello, World!",
        "Héllo café",
        "Привет мир",
        "你好世界",
        "مرحبا بالعالم",
        "🚀💊🔐✅❌",
        "line\nbreak",
        'quote"inside',
        "back\\slash",
        "null\x00byte",
        "tab\there",
        "",
        " ",
        "a" * 10000,
    ]

    @pytest.mark.parametrize("text", UNICODE_STRINGS)
    def test_unicode_in_trigger_request(self, text, tmp_path):
        seal = Seal(key_path=tmp_path / "key", enable_pq=False)
        capsule = Capsule(
            trigger=TriggerSection(request=text, timestamp=FIXED_TIME),
        )
        seal.seal(capsule)
        assert seal.verify(capsule) is True, (
            f"Verification failed for trigger.request={text!r}"
        )

    @pytest.mark.parametrize("text", UNICODE_STRINGS)
    def test_unicode_survives_roundtrip(self, text):
        capsule = Capsule(
            trigger=TriggerSection(request=text, timestamp=FIXED_TIME),
        )
        restored = Capsule.from_dict(capsule.to_dict())
        assert restored.trigger.request == text, (
            f"Roundtrip lost Unicode: {text!r} -> {restored.trigger.request!r}"
        )

    @pytest.mark.parametrize("text", UNICODE_STRINGS)
    def test_unicode_hash_is_deterministic(self, text):
        capsule = Capsule(
            trigger=TriggerSection(request=text, timestamp=FIXED_TIME),
        )
        h1 = compute_hash(capsule.to_dict())
        h2 = compute_hash(capsule.to_dict())
        assert h1 == h2, (
            f"Hash non-deterministic for text={text!r}: {h1} != {h2}"
        )


# =========================================================================
# BLACK SWAN: Seal fields are NOT part of content hash
# "If seal metadata affects the hash, re-sealing changes the record"
# =========================================================================


class TestSealFieldIsolation:

    def test_hash_is_independent_of_seal_metadata(self, tmp_path):
        """Seal fields must NOT be included in the hash computation."""
        capsule = _fully_populated_capsule()
        content_hash = compute_hash(capsule.to_dict())

        seal = Seal(key_path=tmp_path / "key", enable_pq=False)
        seal.seal(capsule)

        assert capsule.hash == content_hash, (
            "Hash changed after sealing — seal fields are leaking into "
            "the content hash. This means re-sealing changes the record."
        )

    def test_to_dict_excludes_seal_fields(self):
        capsule = _fully_populated_capsule()
        capsule.hash = "should_not_appear"
        capsule.signature = "should_not_appear"
        capsule.signature_pq = "should_not_appear"
        capsule.signed_by = "should_not_appear"

        d = capsule.to_dict()
        assert "hash" not in d
        assert "signature" not in d
        assert "signature_pq" not in d
        assert "signed_by" not in d
        assert "signed_at" not in d

    def test_to_sealed_dict_includes_seal_fields(self):
        capsule = _fully_populated_capsule()
        capsule.hash = "test_hash"
        capsule.signature = "test_sig"
        capsule.signature_pq = "test_pq"
        capsule.signed_by = "test_key"

        d = capsule.to_sealed_dict()
        assert d["hash"] == "test_hash"
        assert d["signature"] == "test_sig"
        assert d["signature_pq"] == "test_pq"
        assert d["signed_by"] == "test_key"

        content = capsule.to_dict()
        for key in content:
            assert key in d, f"to_sealed_dict missing content key: {key}"
