---
title: "Capsule Architecture"
description: "Complete technical architecture of Capsule: the 6-section record model, cryptographic sealing, hash chain integrity, and storage backends."
date_modified: "2026-03-07"
ai_context: |
  Full architecture of the Capsule system. Covers the 6-section Capsule model
  (Trigger, Context, Reasoning, Authority, Execution, Outcome), two-tier
  cryptographic sealing (Ed25519 + optional ML-DSA-65), hash chain for temporal
  integrity, CapsuleStorageProtocol, and built-in SQLite/PostgreSQL backends.
  Source: src/qp_capsule/ (capsule.py, seal.py, chain.py, protocol.py, storage.py, storage_pg.py).
---

# Architecture

> **Six sections. One truth. Cryptographically sealed.**

---

## The Axiom

The entire system flows from a single axiom:

```
∀ action: ∃ capsule
"For every action, there exists a Capsule."
```

Every action an AI agent takes produces a Capsule. Every Capsule tells the full story through six sections. Every Capsule is cryptographically sealed. Every Capsule links to the one before it, forming an unbroken chain.

---

## The 6-Section Model

<!-- VERIFIED: reference/python/src/qp_capsule/capsule.py:78-307 -->

Every Capsule has six mandatory sections. Together they answer the complete audit question: what happened, why, who approved it, how, and what was the result.

```
┌─────────────────────────────────────────────────────────┐
│                       CAPSULE                           │
├─────────────┬───────────────────────────────────────────┤
│ 1. Trigger  │ What initiated this action?               │
│ 2. Context  │ What was the state of the system?         │
│ 3. Reasoning│ Why was this decision made?               │
│ 4. Authority│ Who or what approved it?                  │
│ 5. Execution│ What tools were called?                   │
│ 6. Outcome  │ Did it succeed? What changed?             │
├─────────────┴───────────────────────────────────────────┤
│ SHA3-256 hash │ Ed25519 signature │ ML-DSA-65 (opt.)    │
│ Previous hash │ Sequence number   │ Timestamp           │
└─────────────────────────────────────────────────────────┘
```

### Section 1: Trigger

What initiated this action?

<!-- VERIFIED: reference/python/src/qp_capsule/capsule.py:78-100 -->

| Field | Type | Description |
|---|---|---|
| `type` | `str` | Origin: `"user_request"`, `"scheduled"`, `"system"`, `"agent"` |
| `source` | `str` | Who or what triggered it (user ID, agent ID, system name) |
| `timestamp` | `datetime` | When the action was initiated (UTC, timezone-aware) |
| `request` | `str` | The actual request or task description |
| `correlation_id` | `str \| None` | Links related Capsules across distributed operations |
| `user_id` | `str \| None` | Authenticated user ID, if applicable |

### Section 2: Context

What was the state of the system?

<!-- VERIFIED: reference/python/src/qp_capsule/capsule.py:108-119 -->

| Field | Type | Description |
|---|---|---|
| `agent_id` | `str` | Which agent is acting |
| `session_id` | `str \| None` | Conversation or session identifier |
| `environment` | `dict` | Environmental factors (cluster, model, config) |

### Section 3: Reasoning

Why was this decision made?

<!-- VERIFIED: reference/python/src/qp_capsule/capsule.py:174-218 -->

This is the differentiating section. Reasoning is captured **before execution**, not reconstructed afterward. This provides contemporaneous evidence of deliberation with stronger legal and compliance weight than post-hoc explainability.

| Field | Type | Description |
|---|---|---|
| `analysis` | `str` | Initial analysis of the situation |
| `options` | `list[ReasoningOption]` | Structured options with pros, cons, risks, feasibility |
| `options_considered` | `list[str]` | Legacy shorthand for option descriptions |
| `selected_option` | `str` | Which option was chosen |
| `reasoning` | `str` | The rationale for the selection |
| `confidence` | `float` | Confidence score (0.0 to 1.0) |
| `model` | `str \| None` | AI model that made the decision |
| `prompt_hash` | `str \| None` | SHA3-256 hash of the prompt (for audit without exposing content) |

Each `ReasoningOption` includes:

<!-- VERIFIED: reference/python/src/qp_capsule/capsule.py:128-144 -->

| Field | Type | Description |
|---|---|---|
| `id` | `str` | Unique identifier (e.g., `"opt_1"`) |
| `description` | `str` | What this option is |
| `pros` | `list[str]` | Arguments in favor |
| `cons` | `list[str]` | Arguments against |
| `estimated_impact` | `dict` | Scope, severity, reversibility |
| `feasibility` | `float` | 0.0 to 1.0 |
| `risks` | `list[str]` | Known risks |
| `selected` | `bool` | Was this the chosen option? |
| `rejection_reason` | `str` | Why this option was not chosen (required for non-selected) |

The `rejection_reason` field is what makes this more than logging. Every non-selected option must explain *why it was rejected*.

### Section 4: Authority

Who or what approved this action?

<!-- VERIFIED: reference/python/src/qp_capsule/capsule.py:227-246 -->

| Field | Type | Description |
|---|---|---|
| `type` | `str` | `"autonomous"`, `"human_approved"`, `"policy"`, `"escalated"` |
| `approver` | `str \| None` | Human approver identity |
| `policy_reference` | `str \| None` | Policy ID that authorized the action |
| `chain` | `list[dict]` | Multi-level approval chain entries |
| `escalation_reason` | `str \| None` | Why the action was escalated |

### Section 5: Execution

What actually happened?

<!-- VERIFIED: reference/python/src/qp_capsule/capsule.py:255-277 -->

| Field | Type | Description |
|---|---|---|
| `tool_calls` | `list[ToolCall]` | Each tool invocation with arguments, result, duration, errors |
| `duration_ms` | `int` | Total execution time in milliseconds |
| `resources_used` | `dict` | Tokens, compute, cost, or other resource metrics |

Each `ToolCall` includes: `tool`, `arguments`, `result`, `success`, `duration_ms`, `error`.

### Section 6: Outcome

What was the result?

<!-- VERIFIED: reference/python/src/qp_capsule/capsule.py:286-307 -->

| Field | Type | Description |
|---|---|---|
| `status` | `str` | `"pending"`, `"success"`, `"failure"`, `"partial"`, `"blocked"` |
| `result` | `Any` | Detailed result (may be large) |
| `summary` | `str` | Brief human-readable summary |
| `error` | `str \| None` | Error message if failed |
| `side_effects` | `list[str]` | What changed in the system |
| `metrics` | `dict` | Performance and usage metrics |

---

## Cryptographic Sealing

<!-- VERIFIED: reference/python/src/qp_capsule/seal.py:243-300 -->

Every Capsule is cryptographically sealed using a two-tier architecture:

| Tier | Algorithm | Standard | Purpose | Status |
|---|---|---|---|---|
| **1** | SHA3-256 | FIPS 202 | Content integrity (tamper-evident hash) | Required |
| **1** | Ed25519 | RFC 8032 / FIPS 186-5 | Authenticity and non-repudiation | Required |
| **2** | ML-DSA-65 | FIPS 204 | Quantum-resistant signature | Optional (`pip install qp-capsule[pq]`) |

### Sealing Process

```
Capsule.to_dict()
    │
    ▼
Canonical JSON (sorted keys, compact separators)
    │
    ▼
SHA3-256 hash (64 hex characters)
    │
    ├──▶ Ed25519 sign (128 hex characters)     ← ALWAYS
    │
    └──▶ ML-DSA-65 sign (~5 KB hex)            ← if [pq] installed
    │
    ▼
capsule.hash, capsule.signature, capsule.signature_pq,
capsule.signed_at, capsule.signed_by ← filled
```

### Verification Process

<!-- VERIFIED: reference/python/src/qp_capsule/seal.py:338-385 -->

Verification re-derives the hash from content and checks it against the stored hash and signature:

1. Recompute SHA3-256 hash from `capsule.to_dict()` using canonical JSON
2. Compare computed hash to `capsule.hash` (detects content tampering)
3. Verify Ed25519 signature against the hash (detects forgery)
4. Optionally verify ML-DSA-65 signature (if `verify_pq=True`)

If any step fails, `seal.verify()` returns `False`.

### Key Management

<!-- VERIFIED: reference/python/src/qp_capsule/seal.py:122-159, 161-222 -->

| Key | Location | Permissions | Generated |
|---|---|---|---|
| Ed25519 private key | `~/.quantumpipes/key` | `0600` (owner only) | On first `seal()` call |
| ML-DSA-65 secret key | `~/.quantumpipes/key.ml` | `0600` (owner only) | On first PQ `seal()` call |
| ML-DSA-65 public key | `~/.quantumpipes/key.ml.pub` | `0644` (world-readable) | On first PQ `seal()` call |

Override the key directory with the `QUANTUMPIPES_DATA_DIR` environment variable or by passing `key_path` to the `Seal` constructor.

Keys are generated using cryptographically secure random sources. File creation uses `umask(0o077)` to prevent race conditions between creation and permission setting.

---

## Hash Chain

<!-- VERIFIED: reference/python/src/qp_capsule/chain.py:42-145 -->

The hash chain turns individual Capsules into an unbreakable audit trail. Each Capsule records the hash of the one before it.

```
Capsule #0          Capsule #1          Capsule #2
┌──────────┐        ┌──────────┐        ┌──────────┐
│ hash: A  │◀───────│prev: A   │◀───────│prev: B   │
│ prev: ∅  │        │ hash: B  │        │ hash: C  │
│ seq:  0  │        │ seq:  1  │        │ seq:  2  │
└──────────┘        └──────────┘        └──────────┘
```

### Tamper Detection

| Tampering Type | Detection Mechanism |
|---|---|
| Content modified | SHA3-256 hash changes; signature verification fails |
| Record deleted | Sequence gap detected (expected N, got N+2) |
| Record inserted | `previous_hash` mismatch at the insertion point |
| Record reordered | Sequence numbers and `previous_hash` values mismatch |
| Genesis tampered | Genesis Capsule has `previous_hash` set (should be `None`) |

### Chain Verification

`chain.verify()` supports two verification levels:

**Structural** (default, fast): walks every Capsule in sequence order and checks:

1. Sequence numbers are consecutive: 0, 1, 2, ...
2. Each Capsule's `previous_hash` matches the previous Capsule's `hash`
3. The genesis Capsule (sequence 0) has `previous_hash = None`

**Cryptographic** (`verify_content=True`): everything above, plus:

4. Recomputes SHA3-256 from content and compares to stored hash
5. Optionally verifies Ed25519 signatures (when `seal=` is provided)

Structural verification trusts stored hash values. Cryptographic verification catches storage-level tampering where an attacker modifies content without the signing key. See [CPS Section 7.5](../spec/README.md) for the security rationale.

If any check fails, the result includes the Capsule ID where the chain broke and the number of Capsules verified before the break.

### Multi-Tenant Chains

When using PostgreSQL storage, each tenant can have an independent hash chain. Pass `tenant_id` to `chain.add()`, `chain.verify()`, and `chain.seal_and_store()` to scope operations to a specific tenant.

---

## Storage Architecture

<!-- VERIFIED: reference/python/src/qp_capsule/protocol.py:28-90 -->

### CapsuleStorageProtocol

All storage backends implement `CapsuleStorageProtocol`, a runtime-checkable `typing.Protocol` that defines 7 methods:

| Method | Purpose |
|---|---|
| `store(capsule, tenant_id=)` | Persist a sealed Capsule |
| `get(capsule_id)` | Retrieve by ID |
| `get_latest(tenant_id=)` | Get the chain head |
| `get_all_ordered(tenant_id=)` | All Capsules in sequence order |
| `list(limit=, offset=, type_filter=, tenant_id=)` | Paginated retrieval |
| `count(type_filter=, tenant_id=)` | Count with optional filtering |
| `close()` | Release resources |

`CapsuleChain` types against this Protocol, not against a concrete storage class. Any backend that implements these 7 methods plugs directly into the chain.

### Built-in Backends

<!-- VERIFIED: reference/python/src/qp_capsule/storage.py:73-84, src/qp_capsule/storage_pg.py:67-79 -->

| Backend | Install | Table | Multi-Tenant | Use Case |
|---|---|---|---|---|
| `CapsuleStorage` | `qp-capsule[storage]` | `capsules` | No (`tenant_id` accepted, ignored) | Development, single-node |
| `PostgresCapsuleStorage` | `qp-capsule[postgres]` | `quantumpipes_capsules` | Yes (`tenant_id` filters all queries) | Production, multi-tenant |

### Custom Backends

Implement `CapsuleStorageProtocol` to build backends for DynamoDB, Redis, S3, or any other storage system:

```python
from qp_capsule import CapsuleStorageProtocol, CapsuleChain

class MyStorage:
    async def store(self, capsule, tenant_id=None): ...
    async def get(self, capsule_id): ...
    async def get_latest(self, tenant_id=None): ...
    async def get_all_ordered(self, tenant_id=None): ...
    async def list(self, limit=100, offset=0, type_filter=None, tenant_id=None): ...
    async def count(self, type_filter=None, tenant_id=None): ...
    async def close(self): ...

assert isinstance(MyStorage(), CapsuleStorageProtocol)  # runtime check

chain = CapsuleChain(MyStorage())
```

---

## Data Flow

The complete lifecycle of a Capsule:

```
1. CREATE         2. CHAIN           3. SEAL            4. STORE
┌──────────┐     ┌──────────┐      ┌──────────┐      ┌──────────┐
│ Capsule( │────▶│chain.add │─────▶│seal.seal │─────▶│ storage  │
│   trigger│     │  sets    │      │  hashes  │      │  .store  │
│   context│     │  prev_   │      │  signs   │      │  persists│
│   reason │     │  hash +  │      │  Ed25519 │      │  to DB   │
│   auth   │     │  sequence│      │  ML-DSA  │      │          │
│   exec   │     │          │      │  (opt.)  │      │          │
│   outcome│     │          │      │          │      │          │
│ )        │     └──────────┘      └──────────┘      └──────────┘
└──────────┘

5. VERIFY (anytime)
┌──────────────────────────────────────────────┐
│ seal.verify(capsule)    → signature valid?   │
│ chain.verify()          → chain intact?      │
└──────────────────────────────────────────────┘
```

Or in a single call:

```python
capsule = await chain.seal_and_store(capsule, seal)
```

---

## Capsule Types

<!-- VERIFIED: reference/python/src/qp_capsule/capsule.py:44-69 -->

| Type | Value | Purpose |
|---|---|---|
| `AGENT` | `"agent"` | Agent OODA cycle (observe, orient, decide, act) |
| `TOOL` | `"tool"` | Tool invocation |
| `SYSTEM` | `"system"` | System event |
| `KILL` | `"kill"` | Kill switch activation |
| `WORKFLOW` | `"workflow"` | Workflow orchestration |
| `CHAT` | `"chat"` | Chat or RAG interaction |
| `VAULT` | `"vault"` | Secret management and document operations |
| `AUTH` | `"auth"` | Authentication events |

Capsules can form parent-child hierarchies: `WORKFLOW` (parent) -> `AGENT` (child) -> `TOOL` (grandchild), linked by `parent_id`.

---

## Related Documentation

- [Why Capsules](./why-capsules.md) — The case for cryptographic AI memory
- [Security Evaluation](./security.md) — Cryptographic guarantees for CISOs
- [Compliance Mapping](./compliance/) — Regulatory framework alignment
- [CPS Specification](../spec/) — Protocol rules for SDK authors
- [Python Reference](../reference/python/) — Python API reference and quickstart

---

*For every action, there exists a Capsule.*
