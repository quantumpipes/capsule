"""
Tests for Capsule model.

Tests the 6-section Capsule structure and serialization.
"""

from datetime import datetime, timezone
from uuid import UUID

from qp_capsule.capsule import (
    AuthoritySection,
    Capsule,
    CapsuleType,
    ContextSection,
    ExecutionSection,
    OutcomeSection,
    ReasoningSection,
    ToolCall,
    TriggerSection,
)


class TestCapsuleCreation:
    """Test Capsule creation and defaults."""

    def test_create_default_capsule(self):
        """Default Capsule has expected structure."""
        capsule = Capsule()

        assert isinstance(capsule.id, UUID)
        assert capsule.type == CapsuleType.AGENT
        assert capsule.sequence == 0
        assert capsule.previous_hash is None

    def test_capsule_has_six_sections(self):
        """Capsule has all 6 sections."""
        capsule = Capsule()

        assert isinstance(capsule.trigger, TriggerSection)
        assert isinstance(capsule.context, ContextSection)
        assert isinstance(capsule.reasoning, ReasoningSection)
        assert isinstance(capsule.authority, AuthoritySection)
        assert isinstance(capsule.execution, ExecutionSection)
        assert isinstance(capsule.outcome, OutcomeSection)

    def test_capsule_not_sealed_by_default(self):
        """New Capsule is not sealed."""
        capsule = Capsule()

        assert not capsule.is_sealed()
        assert capsule.hash == ""
        assert capsule.signature == ""


class TestTriggerSection:
    """Test Trigger section."""

    def test_trigger_defaults(self):
        """Trigger has sensible defaults."""
        trigger = TriggerSection()

        assert trigger.type == "user_request"
        assert trigger.source == ""
        assert isinstance(trigger.timestamp, datetime)
        assert trigger.request == ""

    def test_trigger_with_values(self):
        """Trigger accepts custom values."""
        trigger = TriggerSection(
            type="system",
            source="scheduler",
            request="Run daily backup",
        )

        assert trigger.type == "system"
        assert trigger.source == "scheduler"
        assert trigger.request == "Run daily backup"


class TestReasoningSection:
    """Test Reasoning section (thoughtfulness requirement)."""

    def test_reasoning_captures_options(self):
        """Reasoning captures options considered."""
        reasoning = ReasoningSection(
            options_considered=["create file", "modify file", "refuse"],
            selected_option="create file",
            reasoning="File doesn't exist, so creating is the right choice",
            confidence=0.9,
        )

        assert len(reasoning.options_considered) == 3
        assert reasoning.selected_option == "create file"
        assert "creating" in reasoning.reasoning
        assert reasoning.confidence == 0.9


class TestExecutionSection:
    """Test Execution section."""

    def test_execution_with_tool_calls(self):
        """Execution captures tool calls."""
        tool_call = ToolCall(
            tool="file_write",
            arguments={"path": "test.txt", "content": "hello"},
            result="File created",
            success=True,
            duration_ms=50,
        )

        execution = ExecutionSection(
            tool_calls=[tool_call],
            duration_ms=100,
        )

        assert len(execution.tool_calls) == 1
        assert execution.tool_calls[0].tool == "file_write"
        assert execution.tool_calls[0].success is True


class TestCapsuleSerialization:
    """Test Capsule to_dict and from_dict."""

    def test_to_dict_produces_valid_structure(self):
        """to_dict produces complete structure."""
        capsule = Capsule(
            type=CapsuleType.AGENT,
            trigger=TriggerSection(
                type="user_request",
                source="user_123",
                request="Create a file",
            ),
            reasoning=ReasoningSection(
                options_considered=["create", "refuse"],
                selected_option="create",
                reasoning="User requested file creation",
                confidence=0.95,
            ),
        )

        data = capsule.to_dict()

        assert "id" in data
        assert data["type"] == "agent"
        assert data["trigger"]["type"] == "user_request"
        assert data["trigger"]["source"] == "user_123"
        assert data["reasoning"]["confidence"] == 0.95

    def test_from_dict_restores_capsule(self):
        """from_dict restores Capsule from dict."""
        original = Capsule(
            type=CapsuleType.TOOL,
            trigger=TriggerSection(
                type="agent",
                source="agent_456",
                request="Execute tool",
            ),
            outcome=OutcomeSection(
                status="success",
                result="Done",
            ),
        )

        data = original.to_dict()
        restored = Capsule.from_dict(data)

        assert restored.id == original.id
        assert restored.type == original.type
        assert restored.trigger.source == original.trigger.source
        assert restored.outcome.status == original.outcome.status

    def test_roundtrip_preserves_data(self):
        """to_dict -> from_dict preserves all data."""
        original = Capsule(
            type=CapsuleType.AGENT,
            sequence=5,
            previous_hash="abc123",
            trigger=TriggerSection(type="system", source="cron", request="Daily task"),
            context=ContextSection(agent_id="agent_1", session_id="sess_1"),
            reasoning=ReasoningSection(
                options_considered=["a", "b"],
                selected_option="a",
                reasoning="a is better",
                confidence=0.8,
            ),
            authority=AuthoritySection(type="policy", policy_reference="POL-001"),
            execution=ExecutionSection(
                tool_calls=[ToolCall(tool="test", arguments={"x": 1}, result="ok", success=True)],
                duration_ms=200,
            ),
            outcome=OutcomeSection(
                status="success",
                result={"data": "value"},
                side_effects=["file_created"],
            ),
        )

        data = original.to_dict()
        restored = Capsule.from_dict(data)

        assert restored.sequence == 5
        assert restored.previous_hash == "abc123"
        assert restored.context.agent_id == "agent_1"
        assert restored.authority.policy_reference == "POL-001"
        assert len(restored.execution.tool_calls) == 1
        assert restored.outcome.side_effects == ["file_created"]


class TestSealedDictSerialization:
    """Test to_sealed_dict / from_sealed_dict roundtrip."""

    def _sealed_capsule(self):
        from datetime import datetime, timezone

        capsule = Capsule(
            type=CapsuleType.AGENT,
            trigger=TriggerSection(source="test", request="test"),
        )
        capsule.hash = "abc123"
        capsule.signature = "sig456"
        capsule.signature_pq = "pq789"
        capsule.signed_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        capsule.signed_by = "key_fingerprint"
        return capsule

    def test_to_sealed_dict_includes_seal_fields(self):
        """to_sealed_dict includes all seal envelope fields."""
        capsule = self._sealed_capsule()

        d = capsule.to_sealed_dict()

        assert d["hash"] == "abc123"
        assert d["signature"] == "sig456"
        assert d["signature_pq"] == "pq789"
        assert d["signed_at"] == "2026-01-01T00:00:00+00:00"
        assert d["signed_by"] == "key_fingerprint"

    def test_to_sealed_dict_superset_of_to_dict(self):
        """to_sealed_dict contains every key from to_dict."""
        capsule = self._sealed_capsule()

        content = capsule.to_dict()
        sealed = capsule.to_sealed_dict()

        for key in content:
            assert key in sealed
            assert sealed[key] == content[key]

    def test_to_sealed_dict_unsealed_has_defaults(self):
        """to_sealed_dict on an unsealed capsule returns empty/None seal fields."""
        capsule = Capsule(
            type=CapsuleType.TOOL,
            trigger=TriggerSection(source="x", request="y"),
        )

        d = capsule.to_sealed_dict()

        assert d["hash"] == ""
        assert d["signature"] == ""
        assert d["signature_pq"] == ""
        assert d["signed_at"] is None
        assert d["signed_by"] == ""

    def test_from_sealed_dict_restores_seal_fields(self):
        """from_sealed_dict restores seal envelope alongside content."""
        capsule = self._sealed_capsule()
        d = capsule.to_sealed_dict()

        restored = Capsule.from_sealed_dict(d)

        assert restored.hash == "abc123"
        assert restored.signature == "sig456"
        assert restored.signature_pq == "pq789"
        assert restored.signed_at == capsule.signed_at
        assert restored.signed_by == "key_fingerprint"
        assert restored.id == capsule.id
        assert restored.type == capsule.type

    def test_sealed_dict_roundtrip(self):
        """to_sealed_dict -> from_sealed_dict preserves all data."""
        capsule = Capsule(
            type=CapsuleType.AGENT,
            sequence=3,
            previous_hash="prev",
            trigger=TriggerSection(source="user", request="do stuff"),
            context=ContextSection(agent_id="ag1"),
            reasoning=ReasoningSection(confidence=0.9),
            authority=AuthoritySection(type="policy"),
            execution=ExecutionSection(
                tool_calls=[ToolCall(tool="t", arguments={}, result="ok", success=True)],
            ),
            outcome=OutcomeSection(status="success", result="done"),
        )
        capsule.hash = "h"
        capsule.signature = "s"
        capsule.signature_pq = "spq"
        capsule.signed_at = datetime.now(tz=timezone.utc)
        capsule.signed_by = "kf"

        d = capsule.to_sealed_dict()
        restored = Capsule.from_sealed_dict(d)

        assert restored.hash == capsule.hash
        assert restored.signature == capsule.signature
        assert restored.sequence == 3
        assert restored.outcome.status == "success"
        assert len(restored.execution.tool_calls) == 1

    def test_from_sealed_dict_tolerates_missing_seal_fields(self):
        """from_sealed_dict works with a plain content dict (no seal keys)."""
        capsule = Capsule(
            type=CapsuleType.TOOL,
            trigger=TriggerSection(source="x", request="y"),
        )
        d = capsule.to_dict()

        restored = Capsule.from_sealed_dict(d)

        assert restored.hash == ""
        assert restored.signature == ""
        assert restored.signed_at is None

    def test_to_sealed_dict_is_json_serializable(self):
        """to_sealed_dict output can be passed to json.dumps without error."""
        import json

        capsule = self._sealed_capsule()
        d = capsule.to_sealed_dict()

        serialized = json.dumps(d)
        assert isinstance(serialized, str)

        roundtripped = json.loads(serialized)
        assert roundtripped["hash"] == "abc123"
        assert roundtripped["signed_at"] == "2026-01-01T00:00:00+00:00"

    def test_to_sealed_dict_does_not_mutate_capsule(self):
        """Calling to_sealed_dict has no side effects on the capsule."""
        capsule = self._sealed_capsule()
        original_hash = capsule.hash
        original_sig = capsule.signature
        original_signed_at = capsule.signed_at

        capsule.to_sealed_dict()
        capsule.to_sealed_dict()

        assert capsule.hash == original_hash
        assert capsule.signature == original_sig
        assert capsule.signed_at == original_signed_at

    def test_to_sealed_dict_adds_exactly_five_keys(self):
        """to_sealed_dict has exactly 5 more keys than to_dict."""
        capsule = self._sealed_capsule()

        content_keys = set(capsule.to_dict().keys())
        sealed_keys = set(capsule.to_sealed_dict().keys())

        added = sealed_keys - content_keys
        assert added == {"hash", "signature", "signature_pq", "signed_at", "signed_by"}

    def test_from_dict_ignores_seal_fields_in_input(self):
        """from_dict does not restore seal fields even when present in data."""
        capsule = self._sealed_capsule()
        d = capsule.to_sealed_dict()

        restored = Capsule.from_dict(d)

        assert restored.hash == ""
        assert restored.signature == ""
        assert restored.signature_pq == ""
        assert restored.signed_at is None
        assert restored.signed_by == ""

    def test_from_sealed_dict_with_partial_seal_fields(self):
        """from_sealed_dict fills defaults for missing seal keys."""
        capsule = Capsule(
            type=CapsuleType.AGENT,
            trigger=TriggerSection(source="x", request="y"),
        )
        d = capsule.to_dict()
        d["hash"] = "only_hash_present"

        restored = Capsule.from_sealed_dict(d)

        assert restored.hash == "only_hash_present"
        assert restored.signature == ""
        assert restored.signature_pq == ""
        assert restored.signed_at is None
        assert restored.signed_by == ""


class TestCapsuleString:
    """Test Capsule string representation."""

    def test_str_shows_key_info(self):
        """String representation shows key info."""
        capsule = Capsule(type=CapsuleType.KILL)
        capsule.outcome.status = "success"

        s = str(capsule)

        assert "Capsule" in s
        assert "kill" in s
        assert "success" in s
        assert "sealed=False" in s


class TestExtendedFields:
    """Test extended fields for platform extensibility."""

    def test_capsule_parent_id_field(self):
        """Capsule has parent_id for hierarchy."""
        parent = Capsule(type=CapsuleType.WORKFLOW)
        child = Capsule(type=CapsuleType.AGENT, parent_id=parent.id)

        assert child.parent_id == parent.id
        assert parent.parent_id is None  # Root has no parent

    def test_capsule_domain_field(self):
        """Capsule has domain for functional grouping."""
        capsule = Capsule(domain="goals")

        assert capsule.domain == "goals"

    def test_capsule_domain_defaults_to_agents(self):
        """Domain defaults to 'agents'."""
        capsule = Capsule()

        assert capsule.domain == "agents"

    def test_trigger_correlation_id(self):
        """Trigger has correlation_id for distributed tracing."""
        trigger = TriggerSection(
            type="user_request",
            source="user_123",
            correlation_id="corr_abc123",
        )

        assert trigger.correlation_id == "corr_abc123"

    def test_trigger_user_id(self):
        """Trigger has user_id for authentication tracking."""
        trigger = TriggerSection(
            type="user_request",
            source="api_gateway",
            user_id="user_alice",
        )

        assert trigger.user_id == "user_alice"

    def test_reasoning_analysis_field(self):
        """Reasoning has analysis field for initial analysis."""
        reasoning = ReasoningSection(
            analysis="Task requires file creation with specific content.",
            options_considered=["create", "modify"],
            selected_option="create",
            reasoning="File doesn't exist",
        )

        assert reasoning.analysis == "Task requires file creation with specific content."

    def test_reasoning_model_field(self):
        """Reasoning has model field for AI model tracking."""
        reasoning = ReasoningSection(
            model="ollama/llama3:8b",
            confidence=0.95,
        )

        assert reasoning.model == "ollama/llama3:8b"

    def test_authority_chain_field(self):
        """Authority has chain field for multi-level approvals."""
        authority = AuthoritySection(
            type="policy",
            chain=[
                {"level": 1, "approver": "auto_policy", "decision": "allow"},
                {"level": 2, "approver": "user_alice", "decision": "confirm"},
            ],
        )

        assert len(authority.chain) == 2
        assert authority.chain[0]["approver"] == "auto_policy"

    def test_authority_escalation_reason(self):
        """Authority has escalation_reason field."""
        authority = AuthoritySection(
            type="escalated",
            approver="admin_jane",
            escalation_reason="Action exceeds autonomous threshold",
        )

        assert authority.escalation_reason == "Action exceeds autonomous threshold"

    def test_outcome_summary_field(self):
        """Outcome has summary field for Layer 1 envelope."""
        outcome = OutcomeSection(
            status="success",
            result={"file": "hello.py", "bytes": 21, "checksum": "abc123"},
            summary="Created hello.py with print statement",
        )

        assert outcome.summary == "Created hello.py with print statement"

    def test_outcome_metrics_field(self):
        """Outcome has metrics field for performance tracking."""
        outcome = OutcomeSection(
            status="success",
            metrics={
                "tokens_in": 500,
                "tokens_out": 150,
                "latency_ms": 234,
                "cost_usd": 0.0012,
            },
        )

        assert outcome.metrics["tokens_in"] == 500
        assert outcome.metrics["cost_usd"] == 0.0012

    def test_roundtrip_preserves_new_fields(self):
        """to_dict -> from_dict preserves all new v1.0.0+ fields."""
        from uuid import uuid4

        parent_id = uuid4()
        original = Capsule(
            type=CapsuleType.AGENT,
            parent_id=parent_id,
            domain="goals",
            trigger=TriggerSection(
                type="agent",
                source="conductor",
                correlation_id="corr_123",
                user_id="user_alice",
            ),
            reasoning=ReasoningSection(
                analysis="Initial situation analysis",
                model="ollama/llama3",
            ),
            authority=AuthoritySection(
                type="policy",
                chain=[{"level": 1, "approver": "auto"}],
                escalation_reason=None,
            ),
            outcome=OutcomeSection(
                status="success",
                summary="Completed successfully",
                metrics={"latency_ms": 100},
            ),
        )

        data = original.to_dict()
        restored = Capsule.from_dict(data)

        # Verify new fields preserved
        assert restored.parent_id == parent_id
        assert restored.domain == "goals"
        assert restored.trigger.correlation_id == "corr_123"
        assert restored.trigger.user_id == "user_alice"
        assert restored.reasoning.analysis == "Initial situation analysis"
        assert restored.reasoning.model == "ollama/llama3"
        assert len(restored.authority.chain) == 1
        assert restored.outcome.summary == "Completed successfully"
        assert restored.outcome.metrics["latency_ms"] == 100

    def test_extended_capsule_types_exist(self):
        """Extended CapsuleTypes are defined."""
        # Extended types for additional use cases
        assert CapsuleType.WORKFLOW.value == "workflow"
        assert CapsuleType.CHAT.value == "chat"
        assert CapsuleType.VAULT.value == "vault"
        assert CapsuleType.AUTH.value == "auth"

    def test_dual_signature_fields_exist(self):
        """Capsule has dual signature fields for belt-and-suspenders approach."""
        capsule = Capsule()

        # Ed25519 signature (classical, required)
        assert hasattr(capsule, "signature")
        assert capsule.signature == ""

        # ML-DSA-65/Dilithium3 signature (post-quantum, optional via [pq])
        assert hasattr(capsule, "signature_pq")
        assert capsule.signature_pq == ""
