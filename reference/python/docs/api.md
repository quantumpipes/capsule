---
title: "API Reference"
description: "Complete API reference for Capsule: every class, method, parameter, and type."
date_modified: "2026-03-18"
ai_context: |
  Complete Python API reference for the qp-capsule package v1.5.1+. Covers Capsule model
  (6 sections, 8 CapsuleTypes, to_dict/to_sealed_dict/from_dict/from_sealed_dict),
  Seal (seal, verify, verify_with_key, compute_hash, keyring integration),
  Keyring (epoch-based key rotation, NIST SP 800-57),
  CapsuleChain (add, verify, seal_and_store), CapsuleStorageProtocol (7 methods),
  CapsuleStorage (SQLite), PostgresCapsuleStorage (multi-tenant), storage schema with
  column constraints (signed_at String(40), signed_by String(32)), exception hierarchy,
  CLI (verify, inspect, keys, hash), and the high-level API: Capsules class, @audit()
  decorator, current() context variable, and mount_capsules() FastAPI integration.
  to_sealed_dict() returns canonical content plus seal envelope (hash, signature,
  signature_pq, signed_at, signed_by). from_sealed_dict() is the inverse.
  FastAPI endpoints use to_sealed_dict() so API responses include the full seal.
---

# API Reference

> **Every class. Every method. Every parameter.**

---

## Quick Reference

```python
from qp_capsule import (
    # High-Level API (v1.1.0+)
    Capsules,

    # Capsule Model
    Capsule, CapsuleType,
    TriggerSection, ContextSection,
    ReasoningOption, ReasoningSection,
    AuthoritySection,
    ExecutionSection, OutcomeSection, ToolCall,

    # Cryptographic Seal
    Seal, compute_hash,

    # Key Management (v1.3.0+)
    Keyring, Epoch,

    # Storage Protocol
    CapsuleStorageProtocol,

    # Hash Chain (requires [storage] or [postgres])
    CapsuleChain, ChainVerificationResult,

    # Storage Backends (requires [storage] or [postgres])
    CapsuleStorage,          # SQLite
    PostgresCapsuleStorage,   # PostgreSQL

    # Exceptions
    CapsuleError, SealError, ChainError, StorageError, KeyringError,
)

# FastAPI Integration (optional, requires fastapi)
from qp_capsule.integrations.fastapi import mount_capsules
```

---

## Capsule

The atomic record. Every action creates one.

<!-- VERIFIED: reference/python/src/qp_capsule/capsule.py:315-374 -->

```python
@dataclass
class Capsule:
    # Identity
    id: UUID                          # Auto-generated UUIDv4
    type: CapsuleType                 # Default: CapsuleType.AGENT
    domain: str                       # Default: "agents"

    # Hierarchy
    parent_id: UUID | None            # Links to parent Capsule

    # Hash Chain
    sequence: int                     # Position in chain (0-indexed)
    previous_hash: str | None         # SHA3-256 hash of previous Capsule

    # The 6 Sections
    trigger: TriggerSection
    context: ContextSection
    reasoning: ReasoningSection
    authority: AuthoritySection
    execution: ExecutionSection
    outcome: OutcomeSection

    # Seal (filled by Seal.seal())
    hash: str                         # SHA3-256 hash of content
    signature: str                    # Ed25519 signature (hex)
    signature_pq: str                 # ML-DSA-65 signature (hex, optional)
    signed_at: datetime | None        # When sealed (UTC)
    signed_by: str                    # Key fingerprint (qp_key_XXXX or legacy 16 hex chars)
```

### Methods

<!-- VERIFIED: reference/python/src/qp_capsule/capsule.py:376-656 -->

**`is_sealed() -> bool`**
Returns `True` if the Capsule has a hash and Ed25519 signature.

**`has_pq_seal() -> bool`**
Returns `True` if the Capsule also has an ML-DSA-65 post-quantum signature.

**`to_dict() -> dict[str, Any]`**
Serialize the canonical content of this Capsule. Returns only the content fields — the part that gets hashed. Seal envelope fields (`hash`, `signature`, `signature_pq`, `signed_at`, `signed_by`) are deliberately excluded to avoid circular dependency during hash computation. For a complete representation including the seal, use `to_sealed_dict()`.

**`to_sealed_dict() -> dict[str, Any]`**
Serialize this Capsule including the cryptographic seal envelope. Returns everything from `to_dict()` plus five additional keys: `hash`, `signature`, `signature_pq`, `signed_at` (ISO 8601 string or `null`), and `signed_by`. Use this when serializing capsules for API responses, exports, or any context where the complete sealed record is needed.

```python
seal.seal(capsule)
d = capsule.to_sealed_dict()

d["id"]           # "a1b2c3d4-..."
d["trigger"]      # {...}
d["hash"]         # "e21819859fce83ea..."  (64-char SHA3-256 hex)
d["signature"]    # "db37397b068c79..."    (Ed25519 hex)
d["signature_pq"] # ""                     (empty if PQ disabled)
d["signed_at"]    # "2026-03-18T02:52:03+00:00"
d["signed_by"]    # "qp_key_a1b2"
```

**`Capsule.from_dict(data: dict) -> Capsule`** *(classmethod)*
Deserialize from a canonical content dictionary. Restores all 6 sections. Seal envelope fields, if present in *data*, are ignored. To restore a complete sealed record, use `from_sealed_dict()`.

**`Capsule.from_sealed_dict(data: dict) -> Capsule`** *(classmethod)*
Deserialize from a sealed dictionary. Restores both the canonical content and the seal envelope fields (`hash`, `signature`, `signature_pq`, `signed_at`, `signed_by`). This is the inverse of `to_sealed_dict()`. Missing seal keys default to empty values.

```python
# Full roundtrip with seal preservation
d = capsule.to_sealed_dict()
restored = Capsule.from_sealed_dict(d)
assert seal.verify(restored)  # True — signature survives the roundtrip
```

**`Capsule.create(capsule_type=, trigger=, context=, reasoning=, authority=, execution=, outcome=, *, domain=, parent_id=) -> Capsule`** *(classmethod)*
Factory method that accepts plain dicts instead of section dataclasses. Unknown keys are silently ignored.

```python
capsule = Capsule.create(
    type=CapsuleType.TOOL,
    trigger={"source": "deploy-bot", "request": "Deploy v2.4"},
    reasoning={"selected_option": "deploy", "confidence": 0.95},
)
```

---

## CapsuleType

<!-- VERIFIED: reference/python/src/qp_capsule/capsule.py:44-69 -->

```python
class CapsuleType(StrEnum):
    AGENT = "agent"         # Agent OODA cycle
    TOOL = "tool"           # Tool invocation
    SYSTEM = "system"       # System event
    KILL = "kill"           # Kill switch activation
    WORKFLOW = "workflow"    # Workflow orchestration
    CHAT = "chat"           # Chat/RAG interaction
    VAULT = "vault"         # Document operations
    AUTH = "auth"           # Authentication events
```

---

## Section Dataclasses

### TriggerSection

<!-- VERIFIED: reference/python/src/qp_capsule/capsule.py:78-100 -->

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | `str` | `"user_request"` | `"user_request"`, `"scheduled"`, `"system"`, `"agent"` |
| `source` | `str` | `""` | Who or what triggered the action |
| `timestamp` | `datetime` | `datetime.now(UTC)` | When action was initiated (UTC) |
| `request` | `str` | `""` | The request or task description |
| `correlation_id` | `str \| None` | `None` | Links related Capsules (distributed tracing) |
| `user_id` | `str \| None` | `None` | Authenticated user ID |

### ContextSection

<!-- VERIFIED: reference/python/src/qp_capsule/capsule.py:108-119 -->

| Field | Type | Default | Description |
|---|---|---|---|
| `agent_id` | `str` | `""` | Which agent is acting |
| `session_id` | `str \| None` | `None` | Session or conversation ID |
| `environment` | `dict[str, Any]` | `{}` | Environmental factors |

### ReasoningOption

<!-- VERIFIED: reference/python/src/qp_capsule/capsule.py:128-144 -->

| Field | Type | Default | Description |
|---|---|---|---|
| `id` | `str` | `""` | Unique ID (e.g., `"opt_1"`) |
| `description` | `str` | `""` | What this option is |
| `pros` | `list[str]` | `[]` | Arguments in favor |
| `cons` | `list[str]` | `[]` | Arguments against |
| `estimated_impact` | `dict` | `{}` | Scope, severity, reversibility |
| `feasibility` | `float` | `0.0` | 0.0 to 1.0 |
| `risks` | `list[str]` | `[]` | Known risks |
| `selected` | `bool` | `False` | Was this the chosen option? |
| `rejection_reason` | `str` | `""` | Why not chosen (required for non-selected) |

### ReasoningSection

<!-- VERIFIED: reference/python/src/qp_capsule/capsule.py:174-202 -->

| Field | Type | Default | Description |
|---|---|---|---|
| `analysis` | `str` | `""` | Initial analysis |
| `options` | `list[ReasoningOption]` | `[]` | Structured options with pros/cons/risks |
| `options_considered` | `list[str]` | `[]` | Legacy shorthand for option descriptions |
| `selected_option` | `str` | `""` | Which option was chosen |
| `reasoning` | `str` | `""` | Rationale for the selection |
| `confidence` | `float` | `0.0` | Confidence score (0.0 to 1.0) |
| `model` | `str \| None` | `None` | AI model used |
| `prompt_hash` | `str \| None` | `None` | SHA3-256 hash of the prompt |

### AuthoritySection

<!-- VERIFIED: reference/python/src/qp_capsule/capsule.py:227-246 -->

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | `str` | `"autonomous"` | `"autonomous"`, `"human_approved"`, `"policy"`, `"escalated"` |
| `approver` | `str \| None` | `None` | Human approver identity |
| `policy_reference` | `str \| None` | `None` | Policy ID |
| `chain` | `list[dict]` | `[]` | Multi-level approval chain |
| `escalation_reason` | `str \| None` | `None` | Why escalation occurred |

### ToolCall

<!-- VERIFIED: reference/python/src/qp_capsule/capsule.py:255-263 -->

| Field | Type | Default | Description |
|---|---|---|---|
| `tool` | `str` | *(required)* | Tool name |
| `arguments` | `dict[str, Any]` | `{}` | Arguments passed to the tool |
| `result` | `Any` | `None` | Return value |
| `success` | `bool` | `False` | Whether the call succeeded |
| `duration_ms` | `int` | `0` | Execution time in milliseconds |
| `error` | `str \| None` | `None` | Error message if failed |

### ExecutionSection

<!-- VERIFIED: reference/python/src/qp_capsule/capsule.py:267-277 -->

| Field | Type | Default | Description |
|---|---|---|---|
| `tool_calls` | `list[ToolCall]` | `[]` | Tool invocations |
| `duration_ms` | `int` | `0` | Total execution time |
| `resources_used` | `dict[str, Any]` | `{}` | Tokens, compute, cost |

### OutcomeSection

<!-- VERIFIED: reference/python/src/qp_capsule/capsule.py:286-307 -->

| Field | Type | Default | Description |
|---|---|---|---|
| `status` | `str` | `"pending"` | `"pending"`, `"success"`, `"failure"`, `"partial"`, `"blocked"` |
| `result` | `Any` | `None` | Detailed result |
| `summary` | `str` | `""` | Brief human-readable summary |
| `error` | `str \| None` | `None` | Error message if failed |
| `side_effects` | `list[str]` | `[]` | What changed in the system |
| `metrics` | `dict[str, Any]` | `{}` | Performance and usage metrics |

---

## Seal

Cryptographic sealing with two-tier architecture.

<!-- VERIFIED: reference/python/src/qp_capsule/seal.py:80-104 -->

```python
class Seal:
    def __init__(
        self,
        key_path: Path | None = None,
        enable_pq: bool | None = None,
        *,
        keyring: Keyring | None = None,
    )
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `key_path` | `Path \| None` | `~/.quantumpipes/key` | Ed25519 private key file path |
| `enable_pq` | `bool \| None` | `None` (auto-detect) | `None` = use ML-DSA-65 if available; `True` = require; `False` = disable |
| `keyring` | `Keyring \| None` | `None` | Keyring for epoch-aware verification. When provided, `verify()` uses the capsule's `signed_by` fingerprint to resolve the correct epoch's public key. |

### Properties

**`pq_enabled: bool`** — Whether post-quantum signatures are active.

### Methods

<!-- VERIFIED: reference/python/src/qp_capsule/seal.py:243-300, 338-385, 417-451, 224-241, 234-241 -->

**`seal(capsule: Capsule) -> Capsule`**
Seal a Capsule. Fills `hash`, `signature`, `signature_pq` (if PQ enabled), `signed_at`, `signed_by`. Raises `SealError` on failure.

**`verify(capsule: Capsule, verify_pq: bool = False) -> bool`**
Verify a sealed Capsule. Returns `True` if hash and Ed25519 signature are valid. When a `keyring` was provided at construction, the capsule's `signed_by` fingerprint is used to look up the correct epoch's public key, enabling verification across key rotations. Set `verify_pq=True` to also verify the ML-DSA-65 signature.

**`verify_with_key(capsule: Capsule, public_key_hex: str) -> bool`**
Verify a Capsule using a specific Ed25519 public key (hex-encoded). Useful for verifying Capsules sealed by other instances.

**`get_public_key() -> str`**
Returns the Ed25519 public key as a 64-character hex string.

**`get_key_fingerprint() -> str`**
Returns the keyring's `qp_key_XXXX` format when a keyring is available with an active epoch, otherwise falls back to the first 16 characters of the hex-encoded public key (legacy format).

### compute_hash

<!-- VERIFIED: reference/python/src/qp_capsule/seal.py:454-467 -->

```python
def compute_hash(data: dict) -> str
```

Standalone SHA3-256 hash of a dictionary. Uses canonical JSON (sorted keys, compact separators). Returns 64-character hex string.

---

## Keyring

> **Added in v1.3.0.**

Epoch-based key lifecycle manager aligned with NIST SP 800-57.

<!-- VERIFIED: reference/python/src/qp_capsule/keyring.py:82-116 -->

```python
class Keyring:
    def __init__(
        self,
        keyring_path: Path | None = None,
        key_path: Path | None = None,
    )
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `keyring_path` | `Path \| None` | `~/.quantumpipes/keyring.json` | Path to keyring file |
| `key_path` | `Path \| None` | `~/.quantumpipes/key` | Path to Ed25519 private key |

On first access, loads from disk. If a key file exists but no keyring file, migrates automatically by creating epoch 0 for the existing key.

### Properties

| Property | Type | Description |
|---|---|---|
| `path` | `Path` | Path to the keyring file |
| `key_path` | `Path` | Path to the Ed25519 private key file |
| `active_epoch` | `int` | Current active epoch number |
| `epochs` | `list[Epoch]` | All epochs (returns a copy) |

### Methods

<!-- VERIFIED: reference/python/src/qp_capsule/keyring.py:220-341 -->

**`load() -> None`**
Load keyring from disk, migrating from existing key files if needed.

**`get_active() -> Epoch | None`**
Get the active epoch, or `None` if no epochs exist.

**`lookup(fingerprint: str) -> Epoch | None`**
Look up an epoch by fingerprint. Matches on the `qp_key_XXXX` format and on the legacy 16-char hex prefix.

**`lookup_public_key(fingerprint: str) -> str | None`**
Look up a public key hex string by fingerprint.

**`rotate() -> Epoch`**
Rotate to a new key pair. Retires the current epoch, generates a new Ed25519 key, writes keyring atomically.

**`register_key(signing_key: SigningKey) -> Epoch`**
Register an existing key in the keyring. Idempotent. Called by `Seal` when generating a key for a keyring that does not yet track it.

**`export_public_key() -> str | None`**
Export the active epoch's public key as a hex string.

**`to_dict() -> dict[str, Any]`**
Serialize keyring to dict.

### Epoch

<!-- VERIFIED: reference/python/src/qp_capsule/keyring.py:46-79 -->

```python
@dataclass
class Epoch:
    epoch: int                # Epoch number (0-indexed)
    algorithm: str            # "ed25519"
    public_key_hex: str       # 64-char hex public key
    fingerprint: str          # "qp_key_XXXX"
    created_at: str           # ISO 8601 timestamp
    rotated_at: str | None    # ISO 8601 timestamp (None if active)
    status: str               # "active" or "retired"
```

---

## CapsuleChain

Hash chain management. Accepts any `CapsuleStorageProtocol` backend.

<!-- VERIFIED: reference/python/src/qp_capsule/chain.py:42-64 -->

```python
class CapsuleChain:
    def __init__(self, storage: CapsuleStorageProtocol)
```

### Methods

<!-- VERIFIED: reference/python/src/qp_capsule/chain.py:66-211 -->

**`async add(capsule: Capsule, tenant_id: str | None = None) -> Capsule`**
Set `previous_hash` and `sequence` based on the current chain head. Does NOT seal or store.

**`async verify(tenant_id: str | None = None) -> ChainVerificationResult`**
Verify the entire chain. Checks consecutive sequence numbers, `previous_hash` linkage, and genesis validity.

**`async verify_capsule_in_chain(capsule: Capsule) -> bool`**
Verify a single Capsule is properly linked.

**`async get_chain_length(tenant_id: str | None = None) -> int`**
Number of Capsules in the chain.

**`async get_chain_head(tenant_id: str | None = None) -> Capsule | None`**
Most recent Capsule, or `None` if empty.

**`async seal_and_store(capsule: Capsule, seal: Seal | None = None, tenant_id: str | None = None) -> Capsule`**
Chain + seal + store in one call. Creates a new `Seal()` if none provided.

### ChainVerificationResult

<!-- VERIFIED: reference/python/src/qp_capsule/chain.py:32-39 -->

```python
@dataclass
class ChainVerificationResult:
    valid: bool                      # Is the chain intact?
    error: str | None = None         # Error description
    broken_at: str | None = None     # Capsule ID where chain broke
    capsules_verified: int = 0       # Number of Capsules verified
```

---

## CapsuleStorageProtocol

<!-- VERIFIED: reference/python/src/qp_capsule/protocol.py:28-90 -->

Runtime-checkable `typing.Protocol`. Any class implementing these 7 methods can be used with `CapsuleChain`.

```python
@runtime_checkable
class CapsuleStorageProtocol(Protocol):
    async def store(self, capsule: Capsule, tenant_id: str | None = None) -> Capsule: ...
    async def get(self, capsule_id: str | UUID) -> Capsule | None: ...
    async def get_latest(self, tenant_id: str | None = None) -> Capsule | None: ...
    async def get_all_ordered(self, tenant_id: str | None = None) -> Sequence[Capsule]: ...
    async def list(self, limit: int = 100, offset: int = 0,
                   type_filter: CapsuleType | None = None,
                   tenant_id: str | None = None) -> Sequence[Capsule]: ...
    async def count(self, type_filter: CapsuleType | None = None,
                    tenant_id: str | None = None) -> int: ...
    async def close(self) -> None: ...
```

Runtime check: `isinstance(my_storage, CapsuleStorageProtocol)` returns `True` for any conforming backend.

---

## CapsuleStorage (SQLite)

<!-- VERIFIED: reference/python/src/qp_capsule/storage.py:73-84 -->

```python
class CapsuleStorage:
    def __init__(self, db_path: Path | None = None)
```

Default path: `~/.quantumpipes/capsules.db` (override with `QUANTUMPIPES_DATA_DIR` env var). Table: `capsules`. Database and tables created automatically on first use.

`tenant_id` is accepted on all methods for interface compatibility but is ignored by SQLite storage.

### Additional Methods

Beyond the Protocol, `CapsuleStorage` also provides:

**`async get_by_hash(hash_value: str) -> Capsule | None`** — Look up by SHA3-256 hash.

**`async list_by_session(session_id: str) -> Sequence[Capsule]`** — Get all Capsules in a session, chronological order. Validates UUID format; returns empty list for invalid input.

---

## PostgresCapsuleStorage

<!-- VERIFIED: reference/python/src/qp_capsule/storage_pg.py:67-79 -->

```python
class PostgresCapsuleStorage:
    def __init__(self, database_url: str)
```

Automatically converts `postgresql://` to `postgresql+asyncpg://`. Table: `quantumpipes_capsules`. Connection pool: 5 connections, 10 max overflow.

`tenant_id` is **active** on this backend: it filters all queries for multi-tenant isolation.

### Additional Parameters

The `list()` and `count()` methods accept extra parameters beyond the Protocol:

| Parameter | Type | Description |
|---|---|---|
| `domain` | `str \| None` | Filter by domain (e.g., `"vault"`, `"agents"`, `"chat"`) |
| `session_id` | `str \| None` | Filter by session ID (on `list()` only) |

**`CapsuleStoragePG`** is preserved as an alias for backward compatibility.

---

## Storage Schema

Both storage backends persist seal metadata in dedicated columns. The column widths are sized to accommodate all values produced by `Seal.seal()`.

<!-- VERIFIED: reference/python/src/qp_capsule/storage.py:60-71 -->
<!-- VERIFIED: reference/python/src/qp_capsule/storage_pg.py:56-68 -->

| Column | Type | Description |
|---|---|---|
| `id` | `String(36)` | UUIDv4 primary key |
| `type` | `String(20)` | `CapsuleType` value |
| `sequence` | `Integer` | Chain position (indexed, unique per tenant) |
| `previous_hash` | `String(64)` | SHA3-256 hash of previous Capsule (nullable) |
| `data` | `Text` | Full Capsule as JSON |
| `hash` | `String(64)` | SHA3-256 content hash (indexed) |
| `signature` | `Text` | Ed25519 signature (hex) |
| `signature_pq` | `Text` | ML-DSA-65 signature (hex, empty if PQ disabled) |
| `signed_at` | `String(40)` | `datetime.isoformat()` — UTC-aware produces 32 chars (e.g., `2026-03-17T05:24:42.485699+00:00`); 40 provides headroom |
| `signed_by` | `String(32)` | Key fingerprint — legacy hex prefix is 16 chars, keyring `qp_key_XXXX` is 11 chars; 32 provides headroom |
| `session_id` | `String(36)` | Conversation session UUID (nullable, indexed) |
| `domain` | `String(50)` | Capsule domain (PostgreSQL only, indexed) |
| `tenant_id` | `String(36)` | Tenant isolation (PostgreSQL only, nullable, indexed) |

### Migration from pre-1.5.1

Versions prior to 1.5.1 used `String(30)` for `signed_at` and `String(16)` for `signed_by`. The `signed_at` column was 2 characters too narrow for UTC-aware `datetime.isoformat()` output, causing `StorageError` on every PostgreSQL write.

For existing PostgreSQL deployments:

```sql
ALTER TABLE quantumpipes_capsules
  ALTER COLUMN signed_at TYPE VARCHAR(40),
  ALTER COLUMN signed_by TYPE VARCHAR(32);
```

SQLite does not enforce `VARCHAR` length, so no migration is needed for SQLite databases.

---

## Exceptions

<!-- VERIFIED: reference/python/src/qp_capsule/exceptions.py:12-29 -->

```
CapsuleError            Base exception for all Capsule operations
├── SealError           Sealing or verification failed
├── ChainError          Hash chain integrity error
├── StorageError        Storage operation failed (e.g., storing unsealed Capsule)
└── KeyringError        Keyring operation failed (load, save, rotate, lookup)
```

All inherit from `CapsuleError`. Catch `CapsuleError` for unified error handling.

---

## Complete Example

```python
import asyncio
from qp_capsule import (
    Capsule, CapsuleType, Seal,
    CapsuleChain, CapsuleStorage,
    TriggerSection, ContextSection,
    ReasoningSection, AuthoritySection,
    ExecutionSection, OutcomeSection, ToolCall,
)

async def main():
    storage = CapsuleStorage()
    chain = CapsuleChain(storage)
    seal = Seal()

    capsule = Capsule(
        type=CapsuleType.AGENT,
        trigger=TriggerSection(
            type="user_request",
            source="ops-team",
            request="Scale web tier to 6 replicas",
        ),
        context=ContextSection(agent_id="infra-agent"),
        reasoning=ReasoningSection(
            options_considered=["Scale to 6", "Scale to 8", "Do nothing"],
            selected_option="Scale to 6",
            reasoning="Handles projected load with 30% headroom",
            confidence=0.92,
        ),
        authority=AuthoritySection(type="policy", policy_reference="AUTO-SCALE-001"),
        execution=ExecutionSection(
            tool_calls=[
                ToolCall(tool="kubectl_scale", arguments={"replicas": 6},
                         result={"status": "scaled"}, success=True, duration_ms=3200),
            ],
            duration_ms=3200,
        ),
        outcome=OutcomeSection(
            status="success",
            summary="Scaled web tier to 6 replicas",
            side_effects=["deployment/web replicas: 4 -> 6"],
        ),
    )

    capsule = await chain.seal_and_store(capsule, seal)

    print(f"ID:       {capsule.id}")
    print(f"Hash:     {capsule.hash[:16]}...")
    print(f"Sequence: {capsule.sequence}")
    print(f"Sealed:   {capsule.is_sealed()}")
    print(f"PQ Seal:  {capsule.has_pq_seal()}")

    assert seal.verify(capsule)

    result = await chain.verify()
    print(f"Chain:    {result.valid} ({result.capsules_verified} verified)")

    await storage.close()

asyncio.run(main())
```

---

## Capsules (High-Level API)

> **Added in v1.1.0.**

Single entry point that owns storage, chain, and seal internally.

<!-- VERIFIED: reference/python/src/qp_capsule/audit.py:130-216 -->

```python
class Capsules:
    def __init__(
        self,
        url: str | None = None,
        *,
        storage: CapsuleStorageProtocol | None = None,
    )
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `url` | `str \| None` | `None` | `None` = SQLite default; `"postgresql://..."` = PostgreSQL; other string = SQLite at path |
| `storage` | `CapsuleStorageProtocol \| None` | `None` | Custom storage backend (overrides `url`) |

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `storage` | `CapsuleStorageProtocol` | The underlying storage backend |
| `chain` | `CapsuleChain` | The hash chain instance |
| `seal` | `Seal` | The Ed25519 sealing instance |

### Methods

**`current() -> Capsule`**
Get the active Capsule inside an `@audit()` decorated function. Raises `RuntimeError` if called outside.

**`async close() -> None`**
Release storage backend resources.

**`audit(*, type, tenant_from=None, tenant_id=None, trigger_from=0, source=None, domain="agents", swallow_errors=True) -> Callable`**
Decorator factory. See below.

---

## @capsules.audit() Decorator

<!-- VERIFIED: reference/python/src/qp_capsule/audit.py:218-389 -->

Wraps any async or sync function with automatic Capsule creation, sealing, and storage.

```python
@capsules.audit(type="agent", tenant_from="site_id")
async def run_agent(task: str, *, site_id: str):
    cap = capsules.current()
    cap.reasoning.model = "gpt-4o"
    result = await llm.complete(task)
    return result
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `type` | `str \| CapsuleType` | *(required)* | Capsule type |
| `tenant_from` | `str \| None` | `None` | Kwarg name to extract `tenant_id` from |
| `tenant_id` | `str \| Callable \| None` | `None` | Static string or `(args, kwargs) -> str` |
| `trigger_from` | `str \| int \| None` | `0` | Arg name or position for `trigger.request` |
| `source` | `str \| None` | `None` | Static `trigger.source` (default: function qualname) |
| `domain` | `str` | `"agents"` | Capsule domain |
| `swallow_errors` | `bool` | `True` | If `True`, capsule failures are logged and swallowed |

**Guarantees:**
- Return value is never modified
- Exceptions are always re-raised
- Timing is not measurably affected
- Capsule errors never block the decorated function (when `swallow_errors=True`)

---

## mount_capsules() (FastAPI Integration)

<!-- VERIFIED: reference/python/src/qp_capsule/integrations/fastapi.py:36-119 -->

```python
from qp_capsule.integrations.fastapi import mount_capsules

mount_capsules(app, capsules, prefix="/api/v1/capsules")
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `app` | `FastAPI` | *(required)* | FastAPI application |
| `capsules` | `Capsules` | *(required)* | Initialized `Capsules` instance |
| `prefix` | `str` | `"/api/v1/capsules"` | URL prefix |

**Endpoints added:**

| Method | Path | Description |
|--------|------|-------------|
| GET | `{prefix}/` | List capsules (query: `limit`, `offset`, `type`, `tenant_id`) |
| GET | `{prefix}/verify` | Verify chain integrity (query: `tenant_id`) |
| GET | `{prefix}/{capsule_id}` | Get capsule by ID (404 if missing) |

All capsule endpoints serialize using `to_sealed_dict()`, so responses include both the canonical content and the cryptographic seal envelope (`hash`, `signature`, `signature_pq`, `signed_at`, `signed_by`).

FastAPI is not a hard dependency. Raises `CapsuleError` if not installed.

**Security note:** These endpoints are read-only and do not add authentication. Protect them with your application's auth middleware in production.

---

## CLI

> **Added in v1.3.0.**

The `capsule` command is installed automatically with the package.

<!-- VERIFIED: reference/python/src/qp_capsule/cli.py:551-598 -->

```bash
capsule verify chain.json                     # Structural (sequence + hash linkage)
capsule verify --full --db capsules.db        # + SHA3-256 recomputation
capsule verify --signatures chain.json        # + Ed25519 via keyring
capsule verify --json chain.json              # Machine-readable JSON
capsule verify --quiet chain.json             # Exit code only (CI/CD gates)

capsule inspect --db capsules.db --seq 47     # Full 6-section display
capsule inspect --db capsules.db --id <uuid>  # Lookup by capsule ID
capsule inspect capsule.json                  # From exported JSON

capsule keys info                             # Epoch history and active key
capsule keys rotate                           # Rotate to new epoch (no downtime)
capsule keys export-public                    # Export active public key (hex)

capsule hash document.pdf                     # SHA3-256 of any file
```

Exit codes: `0` = pass, `1` = fail, `2` = error.

---

## Related Documentation

- [High-Level API Guide](./high-level-api.md) — Full walkthrough with examples
- [Getting Started](./getting-started.md) — Quick introduction with minimal code
- [Architecture](../../../docs/architecture.md) — How these components fit together
- [Security Evaluation](../../../docs/security.md) — Cryptographic guarantees
- [CPS Specification](../../../spec/) — The normative protocol spec

---

*For every action, there exists a Capsule.*
