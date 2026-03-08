#!/usr/bin/env python3
"""
Generate golden test fixtures for cross-language Capsule verification.

Run from the repo root:
    python conformance/generate_fixtures.py

Outputs fixtures.json in the same directory.
"""

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from qp_capsule import (
    AuthoritySection,
    Capsule,
    CapsuleType,
    ContextSection,
    ExecutionSection,
    OutcomeSection,
    ReasoningOption,
    ReasoningSection,
    ToolCall,
    TriggerSection,
)


def canonical_json(d: dict) -> str:
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha3_256_hex(s: str) -> str:
    return hashlib.sha3_256(s.encode("utf-8")).hexdigest()


def make_fixture(name: str, description: str, capsule: Capsule) -> dict:
    d = capsule.to_dict()
    cj = canonical_json(d)
    h = sha3_256_hex(cj)
    return {
        "name": name,
        "description": description,
        "capsule_dict": d,
        "canonical_json": cj,
        "sha3_256_hash": h,
    }


FIXED_TIME = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
FIXED_UUID_1 = UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
FIXED_UUID_2 = UUID("b2c3d4e5-f6a7-8901-bcde-f12345678901")
FIXED_UUID_3 = UUID("c3d4e5f6-a7b8-9012-cdef-123456789012")

fixtures = []

# --- Fixture 1: Minimal capsule (all defaults) ---
c1 = Capsule(id=FIXED_UUID_1, type=CapsuleType.AGENT)
c1.trigger.timestamp = FIXED_TIME
fixtures.append(make_fixture(
    "minimal",
    "Minimal capsule with all defaults. Tests float serialization (confidence: 0.0) "
    "and null handling.",
    c1,
))

# --- Fixture 2: Full capsule with all sections populated ---
c2 = Capsule(
    id=FIXED_UUID_2,
    type=CapsuleType.AGENT,
    domain="goals",
    parent_id=FIXED_UUID_1,
    sequence=5,
    previous_hash="a" * 64,
    trigger=TriggerSection(
        type="user_request",
        source="user_alice",
        timestamp=FIXED_TIME,
        request="Deploy service v2.4 to production",
        correlation_id="corr_abc123",
        user_id="user_alice",
    ),
    context=ContextSection(
        agent_id="executor_001",
        session_id="sess_def456",
        environment={"cwd": "/workspace", "os": "linux", "python": "3.12"},
    ),
    reasoning=ReasoningSection(
        analysis="Production deployment requires blue-green strategy.",
        options=[
            ReasoningOption(
                id="opt_0",
                description="Blue-green deployment",
                pros=["Zero downtime", "Easy rollback"],
                cons=["Requires double resources temporarily"],
                estimated_impact={"scope": "production", "severity": "medium"},
                feasibility=0.9,
                risks=["DNS propagation delay"],
                selected=True,
                rejection_reason="",
            ),
            ReasoningOption(
                id="opt_1",
                description="Rolling update",
                pros=["Simple"],
                cons=["Brief downtime possible"],
                estimated_impact={"scope": "production", "severity": "low"},
                feasibility=0.7,
                risks=["Partial deployment state"],
                selected=False,
                rejection_reason="Higher risk of downtime",
            ),
        ],
        options_considered=["Blue-green deployment", "Rolling update"],
        selected_option="Blue-green deployment",
        reasoning="Blue-green provides zero-downtime with easy rollback capability",
        confidence=0.95,
        model="anthropic/claude-sonnet-4-20250514",
        prompt_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    authority=AuthoritySection(
        type="human_approved",
        approver="user_alice",
        policy_reference="POLICY-PROD-DEPLOY-001",
        chain=[
            {"level": 1, "approver": "auto_policy", "decision": "escalate"},
            {"level": 2, "approver": "user_alice", "decision": "approved"},
        ],
        escalation_reason="Production deployment requires human approval",
    ),
    execution=ExecutionSection(
        tool_calls=[
            ToolCall(
                tool="kubectl_apply",
                arguments={"manifest": "deploy-v2.4.yaml", "namespace": "production"},
                result={"pods_created": 3, "service_updated": True},
                success=True,
                duration_ms=4500,
                error=None,
            ),
            ToolCall(
                tool="health_check",
                arguments={"url": "https://api.example.com/health", "timeout": 30},
                result={"status": 200, "latency_ms": 45},
                success=True,
                duration_ms=1200,
                error=None,
            ),
        ],
        duration_ms=5700,
        resources_used={"cpu_seconds": 2.5, "api_calls": 3},
    ),
    outcome=OutcomeSection(
        status="success",
        result={"version": "2.4", "replicas": 3, "endpoint": "https://api.example.com"},
        summary="Deployed v2.4 to production with 3 replicas, all health checks passing",
        error=None,
        side_effects=["Updated production deployment", "DNS records updated"],
        metrics={"tokens_in": 1500, "tokens_out": 350, "latency_ms": 5700, "cost_usd": 0.0042},
    ),
)
fixtures.append(make_fixture(
    "full",
    "Fully populated capsule with all sections, nested options, tool calls, and metrics. "
    "Tests recursive key sorting, float formatting, and complex nested structures.",
    c2,
))

# --- Fixture 3: Kill switch capsule ---
c3 = Capsule(
    id=FIXED_UUID_3,
    type=CapsuleType.KILL,
    domain="system",
    trigger=TriggerSection(
        type="system",
        source="kill_switch",
        timestamp=FIXED_TIME,
        request="Emergency stop: unexpected behavior detected",
    ),
    authority=AuthoritySection(
        type="autonomous",
    ),
    outcome=OutcomeSection(
        status="blocked",
        summary="All agents terminated via hard kill",
        error="Kill switch activated: mode=hard, reason=unexpected behavior",
        side_effects=["All running agents terminated", "Pending tasks cancelled"],
    ),
)
fixtures.append(make_fixture(
    "kill_switch",
    "Kill switch capsule with blocked status. Tests CapsuleType enum and minimal population.",
    c3,
))


# =============================================================================
# Additional fixtures for comprehensive cross-language conformance
# =============================================================================

FIXED_UUID_4 = UUID("d4e5f6a7-b8c9-0123-defa-234567890123")
FIXED_UUID_5 = UUID("e5f6a7b8-c9d0-1234-efab-345678901234")
FIXED_UUID_6 = UUID("f6a7b8c9-d0e1-2345-fabc-456789012345")
FIXED_UUID_7 = UUID("a7b8c9d0-e1f2-3456-abcd-567890123456")
FIXED_UUID_8 = UUID("b8c9d0e1-f2a3-4567-bcde-678901234567")
FIXED_UUID_9 = UUID("c9d0e1f2-a3b4-5678-cdef-789012345678")
FIXED_UUID_10 = UUID("d0e1f2a3-b4c5-6789-defa-890123456789")
FIXED_UUID_11 = UUID("e1f2a3b4-c5d6-7890-efab-901234567890")
FIXED_UUID_12 = UUID("f2a3b4c5-d6e7-8901-fabc-012345678901")
FIXED_UUID_13 = UUID("a3b4c5d6-e7f8-9012-abcd-123456789abc")
FIXED_UUID_14 = UUID("b4c5d6e7-f8a9-0123-bcde-23456789abcd")
FIXED_UUID_15 = UUID("c5d6e7f8-a9b0-1234-cdef-3456789abcde")
FIXED_UUID_16 = UUID("d6e7f8a9-b0c1-2345-defa-456789abcdef")

# --- Fixture 4: Tool invocation ---
fixtures.append(make_fixture(
    "tool_invocation",
    "Tool-type capsule. Tests CapsuleType.TOOL and tool_calls with error field.",
    Capsule(
        id=FIXED_UUID_4,
        type=CapsuleType.TOOL,
        trigger=TriggerSection(type="agent", source="executor_001", timestamp=FIXED_TIME,
                               request="Read file contents"),
        execution=ExecutionSection(
            tool_calls=[
                ToolCall(tool="file_read", arguments={"path": "/etc/hostname"},
                         result="prod-server-01", success=True, duration_ms=2),
            ],
            duration_ms=2,
        ),
        outcome=OutcomeSection(status="success", result="prod-server-01",
                               summary="Read /etc/hostname"),
    ),
))

# --- Fixture 5: Chat interaction ---
fixtures.append(make_fixture(
    "chat_interaction",
    "Chat-type capsule with session_id. Tests CapsuleType.CHAT and session tracking.",
    Capsule(
        id=FIXED_UUID_5,
        type=CapsuleType.CHAT,
        domain="chat",
        trigger=TriggerSection(type="user_request", source="hub_chat", timestamp=FIXED_TIME,
                               request="What is the capital of France?",
                               user_id="user@example.com"),
        context=ContextSection(agent_id="chat-agent", session_id="sess-chat-001",
                               environment={"model": "gpt-4o", "turn": 3}),
        reasoning=ReasoningSection(
            options_considered=["Answer from knowledge"],
            selected_option="Answer from knowledge",
            reasoning="Factual question with known answer",
            confidence=0.99,
        ),
        outcome=OutcomeSection(status="success", result="Paris",
                               summary="Answered: Paris"),
    ),
))

# --- Fixture 6: Workflow with parent_id (hierarchy) ---
fixtures.append(make_fixture(
    "workflow_hierarchy",
    "Workflow capsule with parent_id. Tests hierarchy linking and CapsuleType.WORKFLOW.",
    Capsule(
        id=FIXED_UUID_6,
        type=CapsuleType.WORKFLOW,
        domain="agents",
        parent_id=FIXED_UUID_1,
        trigger=TriggerSection(type="system", source="orchestrator", timestamp=FIXED_TIME,
                               request="Execute deployment pipeline"),
        outcome=OutcomeSection(status="success", summary="Pipeline completed"),
    ),
))

# --- Fixture 7: Unicode strings ---
fixtures.append(make_fixture(
    "unicode_strings",
    "Capsule with Unicode in multiple fields. Tests UTF-8 serialization across languages.",
    Capsule(
        id=FIXED_UUID_7,
        type=CapsuleType.AGENT,
        trigger=TriggerSection(
            type="user_request",
            source="utilisateur_fran\u00e7ais",
            timestamp=FIXED_TIME,
            request="D\u00e9ployer le service \u00e0 la production \u2014 priorit\u00e9 haute",
        ),
        context=ContextSection(
            agent_id="agent-\u03b1",
            environment={"region": "\u6771\u4eac", "note": "caf\u00e9 \u2603 \u2764"},
        ),
        reasoning=ReasoningSection(
            analysis="\u00c9valuation des risques termin\u00e9e",
            options_considered=["\u00c9tape 1: pr\u00e9paration", "\u00c9tape 2: ex\u00e9cution"],
            selected_option="\u00c9tape 2: ex\u00e9cution",
            reasoning="L'option pr\u00e9sente le meilleur rapport b\u00e9n\u00e9fice/risque",
            confidence=0.88,
        ),
        outcome=OutcomeSection(status="success",
                               summary="D\u00e9ploiement r\u00e9ussi \u2713"),
    ),
))

# --- Fixture 8: Fractional-second timestamp ---
FIXED_TIME_FRAC = datetime(2026, 6, 15, 8, 30, 45, 123456, tzinfo=UTC)
fixtures.append(make_fixture(
    "fractional_timestamp",
    "Capsule with microsecond-precision timestamp. "
    "Tests datetime.isoformat() with fractional seconds.",
    Capsule(
        id=FIXED_UUID_8,
        type=CapsuleType.SYSTEM,
        domain="system",
        trigger=TriggerSection(type="system", source="heartbeat", timestamp=FIXED_TIME_FRAC,
                               request="System health check"),
        outcome=OutcomeSection(status="success", summary="All systems nominal"),
    ),
))

# --- Fixture 9: Empty strings vs null distinction ---
fixtures.append(make_fixture(
    "empty_vs_null",
    "Tests distinction between empty strings and null. source is empty string, "
    "correlation_id is null, user_id is null. Critical for languages that conflate empty/null.",
    Capsule(
        id=FIXED_UUID_9,
        type=CapsuleType.AGENT,
        trigger=TriggerSection(type="user_request", source="", timestamp=FIXED_TIME,
                               request="", correlation_id=None, user_id=None),
        context=ContextSection(agent_id="", session_id=None, environment={}),
        reasoning=ReasoningSection(analysis="", selected_option="",
                                   reasoning="", confidence=0.0,
                                   model=None, prompt_hash=None),
        outcome=OutcomeSection(status="pending", result=None, summary="",
                               error=None),
    ),
))

# --- Fixture 10: Confidence 1.0 (integer-like float) ---
fixtures.append(make_fixture(
    "confidence_one",
    "Confidence exactly 1.0. Tests that float-typed fields serialize as 1.0, not 1. "
    "Critical for Go, Rust, and JavaScript which don't distinguish float from int.",
    Capsule(
        id=FIXED_UUID_10,
        type=CapsuleType.AGENT,
        trigger=TriggerSection(type="agent", source="self", timestamp=FIXED_TIME,
                               request="Self-evaluation"),
        reasoning=ReasoningSection(
            options=[
                ReasoningOption(id="opt_0", description="Only option",
                                feasibility=1.0, selected=True),
            ],
            selected_option="Only option",
            reasoning="No alternatives",
            confidence=1.0,
        ),
        outcome=OutcomeSection(status="success", summary="Completed with full confidence"),
    ),
))

# --- Fixture 11: Deep nesting in environment ---
fixtures.append(make_fixture(
    "deep_nesting",
    "Deeply nested objects in environment and resources_used. Tests recursive key sorting.",
    Capsule(
        id=FIXED_UUID_11,
        type=CapsuleType.AGENT,
        trigger=TriggerSection(type="system", source="scheduler", timestamp=FIXED_TIME,
                               request="Run nested config job"),
        context=ContextSection(
            agent_id="deep-agent",
            environment={
                "z_last": "sorted last",
                "a_first": "sorted first",
                "config": {
                    "nested": {
                        "deep": {"value": 42, "flag": True},
                    },
                    "array": [3, 1, 2],
                },
            },
        ),
        execution=ExecutionSection(
            duration_ms=100,
            resources_used={
                "memory": {"peak_mb": 256, "avg_mb": 128},
                "cpu": {"cores": 4, "utilization": 0.75},
            },
        ),
        outcome=OutcomeSection(status="success", summary="Nested config processed"),
    ),
))

# --- Fixture 12: Chain genesis (sequence 0) ---
fixtures.append(make_fixture(
    "chain_genesis",
    "First capsule in a chain. sequence=0, previous_hash=null. "
    "Tests genesis chain state.",
    Capsule(
        id=FIXED_UUID_12,
        type=CapsuleType.AGENT,
        sequence=0,
        previous_hash=None,
        trigger=TriggerSection(type="user_request", source="cli", timestamp=FIXED_TIME,
                               request="First action in chain"),
        outcome=OutcomeSection(status="success", summary="Genesis capsule"),
    ),
))

# --- Fixture 13: Chain linked (sequence 1) ---
fixtures.append(make_fixture(
    "chain_linked",
    "Second capsule in a chain. sequence=1, previous_hash set to a SHA3-256 hex digest. "
    "Tests chain linking with realistic hash value.",
    Capsule(
        id=FIXED_UUID_13,
        type=CapsuleType.AGENT,
        sequence=1,
        previous_hash="b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
        trigger=TriggerSection(type="user_request", source="cli", timestamp=FIXED_TIME,
                               request="Second action in chain"),
        outcome=OutcomeSection(status="success", summary="Linked capsule"),
    ),
))

# --- Fixture 14: Failure with error ---
fixtures.append(make_fixture(
    "failure_with_error",
    "Failed capsule with error details and failed tool call. Tests error path serialization.",
    Capsule(
        id=FIXED_UUID_14,
        type=CapsuleType.TOOL,
        trigger=TriggerSection(type="agent", source="executor_001", timestamp=FIXED_TIME,
                               request="Delete production database"),
        authority=AuthoritySection(type="policy", policy_reference="DENY-ALL-DESTRUCTIVE"),
        execution=ExecutionSection(
            tool_calls=[
                ToolCall(tool="db_drop", arguments={"database": "production"},
                         result=None, success=False, duration_ms=0,
                         error="Blocked by policy DENY-ALL-DESTRUCTIVE"),
            ],
        ),
        outcome=OutcomeSection(
            status="failure",
            error="Action blocked by safety policy",
            summary="Destructive action denied by policy",
            side_effects=[],
        ),
    ),
))

# --- Fixture 15: Auth capsule with escalation ---
fixtures.append(make_fixture(
    "auth_escalated",
    "Auth-type capsule with escalation chain. Tests CapsuleType.AUTH and authority.chain ordering.",
    Capsule(
        id=FIXED_UUID_15,
        type=CapsuleType.AUTH,
        domain="auth",
        trigger=TriggerSection(type="system", source="auth_service", timestamp=FIXED_TIME,
                               request="MFA challenge for admin action",
                               user_id="admin@example.com"),
        authority=AuthoritySection(
            type="escalated",
            approver="admin@example.com",
            chain=[
                {"level": 1, "method": "password", "result": "passed"},
                {"level": 2, "method": "totp", "result": "passed"},
            ],
            escalation_reason="Admin action requires MFA",
        ),
        outcome=OutcomeSection(status="success",
                               summary="MFA verified, admin access granted"),
    ),
))

# --- Fixture 16: Vault capsule ---
fixtures.append(make_fixture(
    "vault_secret",
    "Vault-type capsule for secret storage/rotation. Tests CapsuleType.VAULT with "
    "tool call for secret rotation and policy-based authority.",
    Capsule(
        id=FIXED_UUID_16,
        type=CapsuleType.VAULT,
        domain="secrets",
        trigger=TriggerSection(type="scheduled", source="secret_rotator", timestamp=FIXED_TIME,
                               request="Rotate database credentials for production"),
        context=ContextSection(agent_id="vault-agent",
                               environment={"vault_backend": "hashicorp", "region": "us-east-1"}),
        authority=AuthoritySection(type="policy", policy_reference="POLICY-SECRET-ROTATION-90D"),
        execution=ExecutionSection(
            tool_calls=[
                ToolCall(tool="vault_rotate", arguments={"secret": "db/prod/credentials",
                                                         "ttl": "90d"},
                         result={"rotated": True, "version": 7},
                         success=True, duration_ms=320),
            ],
            duration_ms=320,
            resources_used={"api_calls": 2},
        ),
        outcome=OutcomeSection(
            status="success",
            result={"secret_path": "db/prod/credentials", "new_version": 7},
            summary="Rotated database credentials, version 7",
            side_effects=["Old credentials revoked after 5m grace period"],
        ),
    ),
))

output = {
    "version": "1.0",
    "specification": "Capsule Protocol Specification v1.0",
    "generated_by": "Python reference implementation (qp-capsule)",
    "generated_at": datetime.now(UTC).isoformat(),
    "description": (
        "Golden test vectors for cross-language Capsule verification. "
        "Each fixture contains a capsule_dict, the expected canonical_json, "
        "and the expected sha3_256_hash. A conformant implementation must "
        "produce byte-identical canonical_json and matching hash for each fixture."
    ),
    "fixtures": fixtures,
}

out_path = Path(__file__).parent / "fixtures.json"
out_path.write_text(json.dumps(output, indent=2, ensure_ascii=False))
print(f"Wrote {len(fixtures)} fixtures to {out_path}")
for f in fixtures:
    print(f"  {f['name']}: hash={f['sha3_256_hash'][:16]}...")
