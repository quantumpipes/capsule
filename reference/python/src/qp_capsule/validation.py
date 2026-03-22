# Copyright 2026 Quantum Pipes Technologies, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Patent Pending — See PATENTS.md for details.

"""
Runtime validation for CPS capsule content dictionaries (FR-002).

Validates structure, types, value ranges, chain rules, and optional integrity
against a claimed SHA3-256 content hash.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from qp_capsule.capsule import CapsuleType
from qp_capsule.seal import compute_hash

_VALID_CAPSULE_TYPES = frozenset(m.value for m in CapsuleType)


def _parse_uuid(s: str) -> UUID | None:
    try:
        return UUID(s)
    except (ValueError, TypeError, AttributeError):
        return None


_ORDERED_TOP_LEVEL = (
    "id",
    "type",
    "domain",
    "parent_id",
    "sequence",
    "previous_hash",
    "spec_version",
    "trigger",
    "context",
    "reasoning",
    "authority",
    "execution",
    "outcome",
)

_REQUIRED_TOP_LEVEL = frozenset(_ORDERED_TOP_LEVEL)

_TRIGGER_KEYS = frozenset(
    ("type", "source", "timestamp", "request", "correlation_id", "user_id")
)
_CONTEXT_KEYS = frozenset(("agent_id", "session_id", "environment"))
_REASONING_KEYS = frozenset(
    (
        "analysis",
        "options",
        "options_considered",
        "selected_option",
        "reasoning",
        "confidence",
        "model",
        "prompt_hash",
    )
)
_AUTHORITY_KEYS = frozenset(
    ("type", "approver", "policy_reference", "chain", "escalation_reason")
)
_EXECUTION_KEYS = frozenset(("tool_calls", "duration_ms", "resources_used"))
_OUTCOME_KEYS = frozenset(
    ("status", "result", "summary", "error", "side_effects", "metrics")
)


@dataclass(frozen=True)
class CapsuleValidationResult:
    """Result of :func:`validate_capsule_dict`."""

    ok: bool
    category: str | None
    field: str | None
    message: str

    @staticmethod
    def success() -> CapsuleValidationResult:
        return CapsuleValidationResult(True, None, None, "")

    @staticmethod
    def fail(
        category: str,
        field: str,
        message: str,
    ) -> CapsuleValidationResult:
        return CapsuleValidationResult(False, category, field, message)


def _is_hex64(s: str) -> bool:
    return len(s) == 64 and all(c in "0123456789abcdef" for c in s.lower())


def _parse_iso8601_utc(ts: str) -> bool:
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return False
    return dt.tzinfo is not None


def validate_capsule_dict(
    data: Any,
    *,
    claimed_hash: str | None = None,
    strict_unknown_keys: bool = False,
) -> CapsuleValidationResult:
    """
    Validate a CPS capsule **content** dictionary (pre-seal / ``to_dict`` shape).

    Does not require seal fields (``hash``, ``signature``, …). When
    *claimed_hash* is set, recomputes SHA3-256 over *data* (canonical JSON
    rules must match :func:`qp_capsule.seal.compute_hash`) and fails with
    ``integrity_violation`` if it differs.

    Args:
        data: Parsed JSON object (must be a ``dict`` at the root).
        claimed_hash: Optional hex digest to check against recomputed hash
            (e.g. tampered-content conformance vectors).
        strict_unknown_keys: If True, reject unknown top-level keys.

    Returns:
        :class:`CapsuleValidationResult` with ``ok`` and error details.
    """
    if not isinstance(data, dict):
        return CapsuleValidationResult.fail(
            "wrong_type",
            "",
            "capsule root must be a JSON object",
        )

    if strict_unknown_keys:
        extra = set(data.keys()) - _REQUIRED_TOP_LEVEL
        if extra:
            name = sorted(extra)[0]
            return CapsuleValidationResult.fail(
                "invalid_value",
                name,
                f"unknown top-level key: {name!r}",
            )

    for key in _ORDERED_TOP_LEVEL:
        if key not in data:
            return CapsuleValidationResult.fail(
                "missing_field",
                key,
                f"missing required field {key!r}",
            )

    # Top-level types and values
    if not isinstance(data["id"], str) or _parse_uuid(data["id"]) is None:
        return CapsuleValidationResult.fail(
            "invalid_value" if isinstance(data["id"], str) else "wrong_type",
            "id",
            "id must be a UUID string",
        )

    if not isinstance(data["type"], str):
        return CapsuleValidationResult.fail("wrong_type", "type", "type must be a string")
    if data["type"] not in _VALID_CAPSULE_TYPES:
        return CapsuleValidationResult.fail(
            "invalid_value",
            "type",
            f"unknown capsule type {data['type']!r}",
        )

    if not isinstance(data["domain"], str):
        return CapsuleValidationResult.fail(
            "wrong_type",
            "domain",
            "domain must be a string",
        )

    pid = data["parent_id"]
    if pid is not None:
        if not isinstance(pid, str) or _parse_uuid(pid) is None:
            return CapsuleValidationResult.fail(
                "invalid_value" if isinstance(pid, str) else "wrong_type",
                "parent_id",
                "parent_id must be null or a UUID string",
            )

    if not isinstance(data["sequence"], int):
        return CapsuleValidationResult.fail(
            "wrong_type",
            "sequence",
            "sequence must be an integer",
        )
    if data["sequence"] < 0:
        return CapsuleValidationResult.fail(
            "invalid_value",
            "sequence",
            "sequence must be non-negative",
        )

    ph = data["previous_hash"]
    if ph is not None:
        if not isinstance(ph, str) or not _is_hex64(ph):
            return CapsuleValidationResult.fail(
                "invalid_value" if isinstance(ph, str) else "wrong_type",
                "previous_hash",
                "previous_hash must be null or a 64-character hex string",
            )

    if not isinstance(data["spec_version"], str) or not data["spec_version"]:
        return CapsuleValidationResult.fail(
            "wrong_type" if not isinstance(data["spec_version"], str) else "invalid_value",
            "spec_version",
            "spec_version must be a non-empty string",
        )

    seq = data["sequence"]
    if seq == 0 and ph is not None:
        return CapsuleValidationResult.fail(
            "chain_violation",
            "previous_hash",
            "genesis capsule (sequence 0) must have previous_hash null",
        )
    if seq != 0 and ph is None:
        return CapsuleValidationResult.fail(
            "chain_violation",
            "previous_hash",
            "non-genesis capsule must have previous_hash set",
        )

    # Sections
    t = data["trigger"]
    if not isinstance(t, dict):
        return CapsuleValidationResult.fail("wrong_type", "trigger", "trigger must be an object")
    for k in _TRIGGER_KEYS:
        if k not in t:
            return CapsuleValidationResult.fail(
                "missing_field",
                f"trigger.{k}",
                f"missing required field trigger.{k!r}",
            )
    if t["type"] is None or not isinstance(t["type"], str):
        return CapsuleValidationResult.fail(
            "wrong_type",
            "trigger.type",
            "trigger.type must be a non-null string",
        )
    if not isinstance(t["timestamp"], str) or not _parse_iso8601_utc(t["timestamp"]):
        return CapsuleValidationResult.fail(
            "invalid_value" if isinstance(t["timestamp"], str) else "wrong_type",
            "trigger.timestamp",
            "trigger.timestamp must be an ISO 8601 string with timezone",
        )

    ctx = data["context"]
    if not isinstance(ctx, dict):
        return CapsuleValidationResult.fail("wrong_type", "context", "context must be an object")
    for k in _CONTEXT_KEYS:
        if k not in ctx:
            return CapsuleValidationResult.fail(
                "missing_field",
                f"context.{k}",
                f"missing required field context.{k!r}",
            )
    if not isinstance(ctx["environment"], dict):
        return CapsuleValidationResult.fail(
            "wrong_type",
            "context.environment",
            "context.environment must be an object",
        )

    r = data["reasoning"]
    if not isinstance(r, dict):
        return CapsuleValidationResult.fail(
            "wrong_type",
            "reasoning",
            "reasoning must be an object",
        )
    for k in _REASONING_KEYS:
        if k not in r:
            return CapsuleValidationResult.fail(
                "missing_field",
                f"reasoning.{k}",
                f"missing required field reasoning.{k!r}",
            )
    conf_raw = r["confidence"]
    if isinstance(conf_raw, bool) or not isinstance(conf_raw, (int, float)):
        return CapsuleValidationResult.fail(
            "wrong_type",
            "reasoning.confidence",
            "reasoning.confidence must be a number",
        )
    c = float(conf_raw)
    if c < 0.0 or c > 1.0:
        return CapsuleValidationResult.fail(
            "invalid_value",
            "reasoning.confidence",
            "reasoning.confidence must be between 0.0 and 1.0",
        )

    a = data["authority"]
    if not isinstance(a, dict):
        return CapsuleValidationResult.fail(
            "wrong_type",
            "authority",
            "authority must be an object",
        )
    for k in _AUTHORITY_KEYS:
        if k not in a:
            return CapsuleValidationResult.fail(
                "missing_field",
                f"authority.{k}",
                f"missing required field authority.{k!r}",
            )

    e = data["execution"]
    if not isinstance(e, dict):
        return CapsuleValidationResult.fail(
            "wrong_type",
            "execution",
            "execution must be an object",
        )
    for k in _EXECUTION_KEYS:
        if k not in e:
            return CapsuleValidationResult.fail(
                "missing_field",
                f"execution.{k}",
                f"missing required field execution.{k!r}",
            )
    if not isinstance(e["tool_calls"], list):
        return CapsuleValidationResult.fail(
            "wrong_type",
            "execution.tool_calls",
            "execution.tool_calls must be an array",
        )
    if not isinstance(e["duration_ms"], int):
        return CapsuleValidationResult.fail(
            "wrong_type",
            "execution.duration_ms",
            "execution.duration_ms must be an integer",
        )
    if not isinstance(e["resources_used"], dict):
        return CapsuleValidationResult.fail(
            "wrong_type",
            "execution.resources_used",
            "execution.resources_used must be an object",
        )

    o = data["outcome"]
    if not isinstance(o, dict):
        return CapsuleValidationResult.fail("wrong_type", "outcome", "outcome must be an object")
    for k in _OUTCOME_KEYS:
        if k not in o:
            return CapsuleValidationResult.fail(
                "missing_field",
                f"outcome.{k}",
                f"missing required field outcome.{k!r}",
            )

    if claimed_hash is not None:
        if not isinstance(claimed_hash, str) or not _is_hex64(claimed_hash):
            return CapsuleValidationResult.fail(
                "invalid_value",
                "hash",
                "claimed_hash must be a 64-character hex string",
            )
        if compute_hash(data) != claimed_hash.lower():
            return CapsuleValidationResult.fail(
                "integrity_violation",
                "hash",
                "content hash does not match claimed_hash",
            )

    return CapsuleValidationResult.success()


def validate_capsule(capsule: Any) -> CapsuleValidationResult:
    """
    Validate a :class:`qp_capsule.capsule.Capsule` instance via its ``to_dict()`` output.
    """
    from qp_capsule.capsule import Capsule as CapsuleCls

    if not isinstance(capsule, CapsuleCls):
        return CapsuleValidationResult.fail(
            "wrong_type",
            "",
            "expected qp_capsule.capsule.Capsule instance",
        )
    return validate_capsule_dict(capsule.to_dict())
