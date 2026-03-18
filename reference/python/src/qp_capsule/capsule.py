# Copyright 2026 Quantum Pipes Technologies, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Patent Pending — See PATENTS.md for details.
# Licensed under the Apache License, Version 2.0 with patent grant (Section 3).

"""
Capsule: The atomic record.

∀ action: ∃ capsule

A Capsule records WHAT happened, WHY it happened, and WHO approved it.
Six sections, one truth. Every action creates a Capsule.

Sections:
    1. Trigger: What initiated this action?
    2. Context: What was the state of the world?
    3. Reasoning: Why was this decision made?
    4. Authority: Who/what approved this action?
    5. Execution: What actually happened?
    6. Outcome: What was the result?

Every Capsule is:
    - Hashed with SHA3-256
    - Signed with Ed25519 (classical, REQUIRED)
    - Optionally dual-signed with ML-DSA-65 (post-quantum, with qp-capsule[pq])
    - Chained to the previous Capsule
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4


def _utc_now() -> datetime:
    """Get current UTC time (timezone-aware)."""
    return datetime.now(UTC)


class CapsuleType(StrEnum):
    """
    Types of recorded actions.

    Core types:
        - AGENT: Agent OODA cycle
        - TOOL: Tool invocation
        - SYSTEM: System event
        - KILL: Kill switch activation

    Extended types:
        - WORKFLOW: Workflow orchestration
        - CHAT: Chat/RAG interaction
        - VAULT: Document operations
        - AUTH: Authentication events
    """

    AGENT = "agent"
    TOOL = "tool"
    SYSTEM = "system"
    KILL = "kill"
    # Extended types
    WORKFLOW = "workflow"
    CHAT = "chat"
    VAULT = "vault"
    AUTH = "auth"


# =============================================================================
# SECTION 1: TRIGGER
# =============================================================================


@dataclass
class TriggerSection:
    """
    What initiated this action?

    Captures the origin of the action - who or what requested it,
    when, and what was requested.

    Fields:
        type: Origin type ("user_request", "scheduled", "system", "agent")
        source: Who/what triggered (user ID, agent ID, system)
        timestamp: When the action was initiated
        request: The actual request/task description
        correlation_id: Links related Capsules across a distributed operation
        user_id: Authenticated user ID (if applicable)
    """

    type: str = "user_request"  # "user_request", "scheduled", "system", "agent"
    source: str = ""  # Who/what triggered (user ID, agent ID, system)
    timestamp: datetime = field(default_factory=_utc_now)
    request: str = ""  # The actual request/task description
    # v1.0.0+: Enable distributed tracing
    correlation_id: str | None = None
    user_id: str | None = None


# =============================================================================
# SECTION 2: CONTEXT
# =============================================================================


@dataclass
class ContextSection:
    """
    What was the state of the world?

    Captures relevant context at the time of action - which agent,
    session, and any environmental factors.
    """

    agent_id: str = ""
    session_id: str | None = None
    environment: dict[str, Any] = field(default_factory=dict)


# =============================================================================
# SECTION 3: REASONING
# =============================================================================


@dataclass
class ReasoningOption:
    """
    A single option considered during AI deliberation (pre-execution).

    Aligns with patent: structured option with pros, cons, impact,
    feasibility, and for non-selected options a rejection_reason.
    """

    id: str = ""  # Unique id within the options array (e.g. "opt_1")
    description: str = ""
    pros: list[str] = field(default_factory=list)
    cons: list[str] = field(default_factory=list)
    estimated_impact: dict[str, Any] = field(default_factory=dict)  # scope, severity, reversibility
    feasibility: float = 0.0  # 0.0 to 1.0
    risks: list[str] = field(default_factory=list)
    selected: bool = False
    rejection_reason: str = ""  # Required for non-selected: why this option was not chosen

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description,
            "pros": self.pros,
            "cons": self.cons,
            "estimated_impact": self.estimated_impact,
            "feasibility": self.feasibility,
            "risks": self.risks,
            "selected": self.selected,
            "rejection_reason": self.rejection_reason,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ReasoningOption:
        return cls(
            id=data.get("id", ""),
            description=data.get("description", ""),
            pros=data.get("pros", []),
            cons=data.get("cons", []),
            estimated_impact=data.get("estimated_impact", {}),
            feasibility=float(data.get("feasibility", 0.0)),
            risks=data.get("risks", []),
            selected=bool(data.get("selected", False)),
            rejection_reason=data.get("rejection_reason", ""),
        )


@dataclass
class ReasoningSection:
    """
    Why was this decision made?

    Every action must show deliberation, not just execution (pre-execution
    capture). Structured options with rejection_reason align with patent.

    Fields:
        analysis: Initial analysis of the situation
        options: Structured options considered (each with rejection_reason if not selected)
        options_considered: Legacy: list of option descriptions (used when options empty)
        selected_option: The chosen option (id or description)
        reasoning: The rationale for the selection
        confidence: Confidence score (0.0 to 1.0)
        model: AI model used (if applicable)
        prompt_hash: SHA3-256 hash of prompt (optional, for audit/privacy tier)
    """

    analysis: str = ""
    options: list[ReasoningOption] = field(default_factory=list)
    options_considered: list[str] = field(
        default_factory=list
    )  # Legacy; used to build options when empty
    selected_option: str = ""
    reasoning: str = ""
    confidence: float = 0.0  # 0.0 to 1.0
    model: str | None = None
    prompt_hash: str | None = None  # Reference to full prompt in privacy tier

    def __post_init__(self) -> None:
        # Backward compat: if options empty but options_considered set, build options
        if not self.options and self.options_considered:
            self.options = [
                ReasoningOption(
                    id=f"opt_{i}",
                    description=d,
                    selected=(d == self.selected_option),
                    rejection_reason="",
                )
                for i, d in enumerate(self.options_considered)
            ]
        # Keep options_considered in sync when options is provided
        # (e.g. from_dict or structured build)
        elif self.options and not self.options_considered:
            self.options_considered = [o.description for o in self.options]


# =============================================================================
# SECTION 4: AUTHORITY
# =============================================================================


@dataclass
class AuthoritySection:
    """
    Who/what approved this action?

    Captures authorization - was this autonomous, human-approved,
    or policy-driven?

    Fields:
        type: Authorization type ("autonomous", "human_approved", "policy", "escalated")
        approver: Who approved (if human)
        policy_reference: Which policy (if policy-driven)
        chain: Authority chain for multi-level approvals
        escalation_reason: Why escalation occurred (if applicable)
    """

    type: str = "autonomous"  # "autonomous", "human_approved", "policy", "escalated"
    approver: str | None = None  # Who approved (if human)
    policy_reference: str | None = None  # Which policy (if policy-driven)
    chain: list[dict[str, Any]] = field(default_factory=list)  # v1.0.0+: Authority chain
    escalation_reason: str | None = None  # v1.0.0+: Why escalation occurred


# =============================================================================
# SECTION 5: EXECUTION
# =============================================================================


@dataclass
class ToolCall:
    """A single tool invocation."""

    tool: str  # Tool name
    arguments: dict[str, Any] = field(default_factory=dict)
    result: Any = None
    success: bool = False
    duration_ms: int = 0
    error: str | None = None


@dataclass
class ExecutionSection:
    """
    What actually happened?

    Captures the concrete actions taken - tool calls, timing,
    and resources used.
    """

    tool_calls: list[ToolCall] = field(default_factory=list)
    duration_ms: int = 0
    resources_used: dict[str, Any] = field(default_factory=dict)


# =============================================================================
# SECTION 6: OUTCOME
# =============================================================================


@dataclass
class OutcomeSection:
    """
    What was the result?

    Captures the final result - success/failure, the actual result,
    any errors, and side effects.

    Fields:
        status: Execution status ("pending", "success", "failure", "partial", "blocked")
        result: The detailed result (may be large, goes to Layer 2/3)
        summary: Brief human-readable summary (stays in Layer 1, permanent)
        error: Error message if failed
        side_effects: List of side effects produced
        metrics: Performance and usage metrics
    """

    status: str = "pending"  # "pending", "success", "failure", "partial", "blocked"
    result: Any = None
    summary: str = ""  # v1.0.0+: Brief summary for Layer 1 envelope
    error: str | None = None
    side_effects: list[str] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)  # v1.0.0+: Performance metrics


# =============================================================================
# THE CAPSULE
# =============================================================================


@dataclass
class Capsule:
    """
    The atomic record.

    ∀ action: ∃ capsule
    "Every action creates a Capsule."

    Every action creates a Capsule. Every Capsule tells the full story
    through its 6 sections. Every Capsule is cryptographically sealed.
    Every Capsule links to the previous, forming an unbroken chain.

    Hierarchy:
        Capsules can form parent-child relationships:
        - WORKFLOW (parent) → AGENT (child) → TOOL (grandchild)
        - parent_id links to the parent Capsule

    Domain:
        Groups Capsules by functional area (agents, goals, vault, chat, etc.)
    """

    # -------------------------------------------------------------------------
    # Identity
    # -------------------------------------------------------------------------
    id: UUID = field(default_factory=uuid4)
    type: CapsuleType = CapsuleType.AGENT
    domain: str = "agents"  # Functional area: "agents", "goals", "vault", "chat"

    # -------------------------------------------------------------------------
    # Hierarchy (for workflow orchestration)
    # -------------------------------------------------------------------------
    parent_id: UUID | None = None  # Links to parent Capsule for hierarchy

    # -------------------------------------------------------------------------
    # Hash Chain (tamper-evident linking)
    # -------------------------------------------------------------------------
    sequence: int = 0  # Position in the hash chain
    previous_hash: str | None = None  # Hash of previous Capsule in chain

    # -------------------------------------------------------------------------
    # The 6 Sections
    # -------------------------------------------------------------------------
    trigger: TriggerSection = field(default_factory=TriggerSection)
    context: ContextSection = field(default_factory=ContextSection)
    reasoning: ReasoningSection = field(default_factory=ReasoningSection)
    authority: AuthoritySection = field(default_factory=AuthoritySection)
    execution: ExecutionSection = field(default_factory=ExecutionSection)
    outcome: OutcomeSection = field(default_factory=OutcomeSection)

    # -------------------------------------------------------------------------
    # Seal (Two-Tier: Classical + Optional Post-Quantum)
    # Tier 1: Ed25519 (always) — proven classical security
    # Tier 2: Ed25519 + ML-DSA-65 (with [pq]) — adds quantum resistance
    # -------------------------------------------------------------------------
    hash: str = ""
    signature: str = ""  # Ed25519 signature (classical, required)
    signature_pq: str = ""  # ML-DSA-65/Dilithium3 (post-quantum, optional with [pq])
    signed_at: datetime | None = None
    signed_by: str = ""  # Key fingerprint

    def is_sealed(self) -> bool:
        """
        Check if Capsule has been sealed.

        A Capsule is sealed when it has at minimum a SHA3-256 hash and an
        Ed25519 signature. Post-quantum (ML-DSA-65) signature is optional
        and depends on whether qp-capsule[pq] is installed.

        Returns:
            True if the Capsule has a hash and Ed25519 signature.
        """
        return bool(self.hash and self.signature)

    def has_pq_seal(self) -> bool:
        """Check if Capsule also has a post-quantum ML-DSA-65 signature."""
        return bool(self.hash and self.signature and self.signature_pq)

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize the canonical content of this Capsule.

        Returns only the content fields — the part that gets hashed.
        Seal envelope fields (hash, signature, signed_at, etc.) are
        deliberately excluded to avoid circular dependency during
        hash computation.

        For a complete representation including the seal, use
        :meth:`to_sealed_dict`.
        """
        return {
            "id": str(self.id),
            "type": self.type.value,
            "domain": self.domain,
            "parent_id": str(self.parent_id) if self.parent_id else None,
            # Hash chain
            "sequence": self.sequence,
            "previous_hash": self.previous_hash,
            "trigger": {
                "type": self.trigger.type,
                "source": self.trigger.source,
                "timestamp": self.trigger.timestamp.isoformat(),
                "request": self.trigger.request,
                "correlation_id": self.trigger.correlation_id,
                "user_id": self.trigger.user_id,
            },
            "context": {
                "agent_id": self.context.agent_id,
                "session_id": self.context.session_id,
                "environment": self.context.environment,
            },
            "reasoning": {
                "analysis": self.reasoning.analysis,
                "options": [o.to_dict() for o in self.reasoning.options],
                "options_considered": [o.description for o in self.reasoning.options]
                if self.reasoning.options
                else self.reasoning.options_considered,
                "selected_option": self.reasoning.selected_option,
                "reasoning": self.reasoning.reasoning,
                "confidence": self.reasoning.confidence,
                "model": self.reasoning.model,
                "prompt_hash": self.reasoning.prompt_hash,
            },
            "authority": {
                "type": self.authority.type,
                "approver": self.authority.approver,
                "policy_reference": self.authority.policy_reference,
                "chain": self.authority.chain,
                "escalation_reason": self.authority.escalation_reason,
            },
            "execution": {
                "tool_calls": [
                    {
                        "tool": tc.tool,
                        "arguments": tc.arguments,
                        "result": tc.result,
                        "success": tc.success,
                        "duration_ms": tc.duration_ms,
                        "error": tc.error,
                    }
                    for tc in self.execution.tool_calls
                ],
                "duration_ms": self.execution.duration_ms,
                "resources_used": self.execution.resources_used,
            },
            "outcome": {
                "status": self.outcome.status,
                "result": self.outcome.result,
                "summary": self.outcome.summary,
                "error": self.outcome.error,
                "side_effects": self.outcome.side_effects,
                "metrics": self.outcome.metrics,
            },
        }

    def to_sealed_dict(self) -> dict[str, Any]:
        """
        Serialize this Capsule including the cryptographic seal envelope.

        Returns everything from :meth:`to_dict` plus the seal fields:
        ``hash``, ``signature``, ``signature_pq``, ``signed_at``, and
        ``signed_by``.

        Use this when serializing capsules for API responses, exports,
        or any context where the complete sealed record is needed.
        """
        d = self.to_dict()
        d["hash"] = self.hash
        d["signature"] = self.signature
        d["signature_pq"] = self.signature_pq
        d["signed_at"] = self.signed_at.isoformat() if self.signed_at else None
        d["signed_by"] = self.signed_by
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Capsule:
        """
        Deserialize Capsule from a canonical content dictionary.

        Restores only the content fields. Seal envelope fields, if
        present in *data*, are ignored. To restore a complete sealed
        record, use :meth:`from_sealed_dict`.
        """
        capsule = cls(
            id=UUID(data["id"]),
            type=CapsuleType(data["type"]),
            domain=data.get("domain", "agents"),
            parent_id=UUID(data["parent_id"]) if data.get("parent_id") else None,
            sequence=data.get("sequence", 0),
            previous_hash=data.get("previous_hash"),
        )

        # Trigger
        t = data.get("trigger", {})
        capsule.trigger = TriggerSection(
            type=t.get("type", "user_request"),
            source=t.get("source", ""),
            timestamp=datetime.fromisoformat(t["timestamp"])
            if t.get("timestamp")
            else datetime.now(UTC),
            request=t.get("request", ""),
            correlation_id=t.get("correlation_id"),
            user_id=t.get("user_id"),
        )

        # Context
        c = data.get("context", {})
        capsule.context = ContextSection(
            agent_id=c.get("agent_id", ""),
            session_id=c.get("session_id"),
            environment=c.get("environment", {}),
        )

        # Reasoning
        r = data.get("reasoning", {})
        options_data = r.get("options", [])
        if options_data:
            options_list = [ReasoningOption.from_dict(opt) for opt in options_data]
            options_considered = [o.description for o in options_list]
        else:
            options_list = []
            options_considered = r.get("options_considered", [])
        capsule.reasoning = ReasoningSection(
            analysis=r.get("analysis", ""),
            options=options_list,
            options_considered=options_considered,
            selected_option=r.get("selected_option", ""),
            reasoning=r.get("reasoning", ""),
            confidence=r.get("confidence", 0.0),
            model=r.get("model"),
            prompt_hash=r.get("prompt_hash"),
        )

        # Authority
        a = data.get("authority", {})
        capsule.authority = AuthoritySection(
            type=a.get("type", "autonomous"),
            approver=a.get("approver"),
            policy_reference=a.get("policy_reference"),
            chain=a.get("chain", []),
            escalation_reason=a.get("escalation_reason"),
        )

        # Execution
        e = data.get("execution", {})
        capsule.execution = ExecutionSection(
            tool_calls=[
                ToolCall(
                    tool=tc.get("tool", ""),
                    arguments=tc.get("arguments", {}),
                    result=tc.get("result"),
                    success=tc.get("success", False),
                    duration_ms=tc.get("duration_ms", 0),
                    error=tc.get("error"),
                )
                for tc in e.get("tool_calls", [])
            ],
            duration_ms=e.get("duration_ms", 0),
            resources_used=e.get("resources_used", {}),
        )

        # Outcome
        o = data.get("outcome", {})
        capsule.outcome = OutcomeSection(
            status=o.get("status", "pending"),
            result=o.get("result"),
            summary=o.get("summary", ""),
            error=o.get("error"),
            side_effects=o.get("side_effects", []),
            metrics=o.get("metrics", {}),
        )

        return capsule

    @classmethod
    def from_sealed_dict(cls, data: dict[str, Any]) -> Capsule:
        """
        Deserialize a Capsule from a sealed dictionary.

        Restores both the canonical content **and** the seal envelope
        fields (``hash``, ``signature``, ``signature_pq``, ``signed_at``,
        ``signed_by``). This is the inverse of :meth:`to_sealed_dict`.
        """
        capsule = cls.from_dict(data)
        capsule.hash = data.get("hash", "")
        capsule.signature = data.get("signature", "")
        capsule.signature_pq = data.get("signature_pq", "")
        signed_at = data.get("signed_at")
        capsule.signed_at = (
            datetime.fromisoformat(signed_at) if signed_at else None
        )
        capsule.signed_by = data.get("signed_by", "")
        return capsule

    @classmethod
    def create(
        cls,
        capsule_type: CapsuleType = CapsuleType.AGENT,
        trigger: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
        reasoning: dict[str, Any] | None = None,
        authority: dict[str, Any] | None = None,
        execution: dict[str, Any] | None = None,
        outcome: dict[str, Any] | None = None,
        *,
        domain: str = "agents",
        parent_id: UUID | None = None,
    ) -> Capsule:
        """
        Create a Capsule from plain dicts.

        Library consumers use this instead of constructing section
        dataclasses manually. Unknown keys in dicts are silently
        ignored via dataclass field filtering.
        """
        import dataclasses

        def _safe_init(section_cls: type, data: dict[str, Any] | None) -> Any:
            if not data:
                return section_cls()
            valid_fields = {f.name for f in dataclasses.fields(section_cls)}
            filtered = {k: v for k, v in data.items() if k in valid_fields}
            return section_cls(**filtered)

        return cls(
            type=capsule_type,
            domain=domain,
            parent_id=parent_id,
            trigger=_safe_init(TriggerSection, trigger),
            context=_safe_init(ContextSection, context),
            reasoning=_safe_init(ReasoningSection, reasoning),
            authority=_safe_init(AuthoritySection, authority),
            execution=_safe_init(ExecutionSection, execution),
            outcome=_safe_init(OutcomeSection, outcome),
        )

    def __str__(self) -> str:
        """Human-readable representation."""
        return (
            f"Capsule({self.id}, type={self.type.value}, "
            f"status={self.outcome.status}, sealed={self.is_sealed()})"
        )
