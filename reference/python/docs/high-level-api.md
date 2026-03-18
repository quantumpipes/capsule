# High-Level API

> **Added in v1.1.0** — One class, one decorator, one context variable.

The high-level API wraps the Capsule primitives (Capsule, Seal, CapsuleChain, Storage) into a convenience layer where integrating audit trails into any Python application requires zero boilerplate.

---

## Quick Start

```python
from qp_capsule import Capsules

capsules = Capsules()  # SQLite, zero config

@capsules.audit(type="agent")
async def run_agent(task: str):
    result = await my_llm.complete(task)
    return result

await run_agent("Write a blog post about AI safety")
# A sealed, hash-chained Capsule now exists in storage.
```

---

## `Capsules` Class

The single entry point. Owns storage, chain, and seal internally.

### Initialization

```python
# Zero-config (SQLite at ~/.quantumpipes/capsules.db)
capsules = Capsules()

# Explicit SQLite path
capsules = Capsules("/path/to/audit.db")

# PostgreSQL
capsules = Capsules("postgresql://user:pass@localhost/mydb")

# Custom storage backend
capsules = Capsules(storage=my_custom_backend)
```

Constructor logic:
- No arguments → `CapsuleStorage()` (SQLite, default path)
- String starting with `postgresql` → `PostgresCapsuleStorage(url)`
- Other string → `CapsuleStorage(Path(url))` (SQLite at specified path)
- `storage=` kwarg → uses the provided backend directly (must satisfy `CapsuleStorageProtocol`)

A `Seal()` and `CapsuleChain(storage)` are created automatically.

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `capsules.storage` | `CapsuleStorageProtocol` | The underlying storage backend |
| `capsules.chain` | `CapsuleChain` | The hash chain instance |
| `capsules.seal` | `Seal` | The Ed25519 sealing instance |

### Cleanup

```python
await capsules.close()
```

Releases storage backend resources. Call this during application shutdown.

---

## `@capsules.audit()` Decorator

Wraps any function with automatic Capsule creation, sealing, and storage.

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `type` | `str \| CapsuleType` | *required* | Capsule type (`"agent"`, `"tool"`, `"chat"`, etc.) |
| `tenant_from` | `str \| None` | `None` | Kwarg name to extract `tenant_id` from |
| `tenant_id` | `str \| Callable \| None` | `None` | Static tenant string or `(args, kwargs) -> str` callable |
| `trigger_from` | `str \| int \| None` | `0` | Arg name or position for `trigger.request` |
| `source` | `str \| None` | `None` | Static `trigger.source` (defaults to function `__qualname__`) |
| `domain` | `str` | `"agents"` | Capsule domain |
| `swallow_errors` | `bool` | `True` | If `True`, capsule failures are logged and swallowed |

### Behavior

**Before execution:**
1. Creates a `Capsule` with the specified type and domain
2. Sets `trigger.source` from `source` param or function qualname
3. Sets `trigger.request` from the specified argument
4. Sets `context.agent_id` to function qualname
5. Stores the Capsule in a context variable (accessible via `capsules.current()`)
6. Records the start time

**After successful execution:**
1. Sets `outcome.status = "success"`
2. Sets `outcome.result` to the return value (safely serialized)
3. Sets `execution.duration_ms` from elapsed time
4. Seals and stores the Capsule via `chain.seal_and_store()`

**After failed execution:**
1. Sets `outcome.status = "failure"`
2. Sets `outcome.error` to the exception message
3. Sets `execution.duration_ms` from elapsed time
4. Seals and stores the Capsule
5. **Re-raises the original exception** — the decorator never changes error behavior

**Error handling:**
- If `swallow_errors=True` (default): any error in capsule creation or sealing is caught and logged via `logging.getLogger("qp_capsule.audit")`. The decorated function is completely unaffected.
- If `swallow_errors=False`: capsule errors propagate (only if the decorated function itself succeeded — a user's exception always takes priority).

### Examples

**Basic:**

```python
@capsules.audit(type="agent")
async def generate_content(prompt: str) -> str:
    return await llm.complete(prompt)
```

**Multi-tenant:**

```python
@capsules.audit(type="agent", tenant_from="site_id")
async def run(task: str, *, site_id: str) -> str:
    return await llm.complete(task)
```

**Custom source:**

```python
@capsules.audit(type="tool", source="content-writer-v2")
async def write(topic: str) -> str:
    return await llm.complete(f"Write about {topic}")
```

**Sync functions:**

```python
@capsules.audit(type="tool")
def compute(value: int) -> int:
    return value * 2
```

Sync functions are supported. Capsule sealing is deferred via `asyncio.create_task()` if an event loop is running, or logged as deferred if not.

---

## `capsules.current()` — Context Variable

Access the active Capsule inside a decorated function to enrich it with runtime data.

```python
@capsules.audit(type="agent")
async def run_agent(task: str) -> str:
    cap = capsules.current()

    # Enrich reasoning
    cap.reasoning.model = "gpt-4o"
    cap.reasoning.confidence = 0.95

    # Enrich context
    cap.context.session_id = "session-abc"

    result = await llm.complete(task)

    # Enrich outcome
    cap.outcome.summary = f"Generated {len(result)} chars"
    cap.execution.resources_used = {"tokens": 1500, "cost_usd": 0.003}

    return result
```

All modifications made via `current()` are persisted when the Capsule is sealed at the end of execution.

**Outside a decorated function:**

```python
capsules.current()
# Raises: RuntimeError("No active capsule — are you inside an @audit decorated function?")
```

---

## FastAPI Integration

Mount three read-only endpoints for inspecting the audit chain.

```python
from fastapi import FastAPI
from qp_capsule import Capsules
from qp_capsule.integrations.fastapi import mount_capsules

app = FastAPI()
capsules = Capsules("postgresql://...")

mount_capsules(app, capsules, prefix="/api/v1/capsules")
```

### Endpoints

All capsule endpoints serialize using `capsule.to_sealed_dict()`, so responses include both the canonical content (the 6 sections) and the cryptographic seal envelope (`hash`, `signature`, `signature_pq`, `signed_at`, `signed_by`).

#### `GET {prefix}/`

List capsules with pagination and filtering.

| Query Param | Type | Default | Description |
|-------------|------|---------|-------------|
| `limit` | int | 20 | Results per page (1-100) |
| `offset` | int | 0 | Skip N results |
| `type` | string | — | Filter by capsule type (e.g. `agent`, `tool`) |
| `tenant_id` | string | — | Filter by tenant (requires PostgreSQL storage) |

**Response:**

```json
{
  "capsules": [
    {
      "id": "a1b2c3d4-...",
      "type": "agent",
      "trigger": { "..." : "..." },
      "hash": "e21819859fce83ea...",
      "signature": "db37397b068c79...",
      "signature_pq": "",
      "signed_at": "2026-03-18T02:52:03+00:00",
      "signed_by": "qp_key_a1b2"
    }
  ],
  "total": 42,
  "limit": 20,
  "offset": 0
}
```

#### `GET {prefix}/{capsule_id}`

Get a single capsule by UUID.

Returns the full sealed capsule dict (content + seal envelope), or 404 if not found.

#### `GET {prefix}/verify`

Verify the integrity of the hash chain.

| Query Param | Type | Default | Description |
|-------------|------|---------|-------------|
| `tenant_id` | string | — | Verify specific tenant's chain |

**Response:**

```json
{
  "valid": true,
  "capsules_verified": 42,
  "error": null,
  "broken_at": null
}
```

### Notes

- FastAPI is **not** a hard dependency. The import is guarded with try/except. If FastAPI is not installed, `mount_capsules()` raises a clear `CapsuleError`.
- Tenant filtering requires PostgreSQL storage. SQLite storage accepts the `tenant_id` parameter for interface compatibility but does not filter by it.

---

## Design Principles

1. **Zero-config default** — `Capsules()` works with no arguments.
2. **Never block the user's code** — capsule errors are swallowed by default.
3. **Never change behavior** — return values, exceptions, and timing are preserved exactly.
4. **Progressively enrichable** — start with just the decorator, add `current()` enrichment later.
5. **Framework-agnostic core** — `audit.py` has zero framework dependencies. FastAPI is optional.
6. **Zero new dependencies** — only stdlib (`contextvars`, `logging`, `inspect`, `functools`).
