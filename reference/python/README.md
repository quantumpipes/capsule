# Capsule Protocol — Python Reference Implementation

> **The canonical implementation of the [Capsule Protocol Specification (CPS)](../../spec/).**

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB.svg)](https://www.python.org/)
[![Coverage](https://img.shields.io/badge/Coverage-100%25-brightgreen.svg)](./pyproject.toml)

---

## Install

```bash
pip install qp-capsule
```

| Command | What You Get | Dependencies |
|---|---|---|
| `pip install qp-capsule` | Create, seal, verify | **1** (pynacl) |
| `pip install qp-capsule[storage]` | + Hash chain + SQLite persistence | **2** (+ sqlalchemy) |
| `pip install qp-capsule[postgres]` | + Hash chain + PostgreSQL (multi-tenant) | **2** (+ sqlalchemy) |
| `pip install qp-capsule[pq]` | + Post-quantum ML-DSA-65 signatures | **2** (+ liboqs) |

---

## Quick Start

```python
from qp_capsule import Capsule, Seal, CapsuleType, TriggerSection

capsule = Capsule(
    type=CapsuleType.AGENT,
    trigger=TriggerSection(
        source="deploy-bot",
        request="Deploy service v2.4 to production",
    ),
)

seal = Seal()
seal.seal(capsule)
assert seal.verify(capsule)
```

### With Hash Chain

```python
from qp_capsule import Capsule, Seal, CapsuleChain, CapsuleStorage, CapsuleType, TriggerSection

storage = CapsuleStorage()
chain = CapsuleChain(storage)
seal = Seal()

capsule = Capsule(
    type=CapsuleType.AGENT,
    trigger=TriggerSection(source="deploy-bot", request="Deploy v2.4"),
)

capsule = await chain.seal_and_store(capsule, seal)

result = await chain.verify()
assert result.valid
```

### High-Level API

```python
from qp_capsule import Capsules

capsules = Capsules()  # SQLite, zero config

@capsules.audit(type="agent")
async def run_agent(task: str, *, site_id: str):
    cap = capsules.current()
    cap.reasoning.model = "gpt-4o"
    cap.reasoning.confidence = 0.92
    result = await llm.complete(task)
    cap.outcome.summary = f"Generated {len(result.text)} chars"
    return result

await run_agent("Write a summary", site_id="tenant-123")
```

### FastAPI Integration

```python
from qp_capsule.integrations.fastapi import mount_capsules

app = FastAPI()
mount_capsules(app, capsules, prefix="/api/v1/capsules")
```

---

## Conformance

This implementation passes all 16 golden test vectors:

```bash
cd reference/python
make test-golden
```

---

## Documentation

| Document | Description |
|---|---|
| [Getting Started](./docs/getting-started.md) | Detailed quickstart |
| [High-Level API](./docs/high-level-api.md) | `Capsules` class, `@audit` decorator |
| [API Reference](./docs/api.md) | Every class and method |
| [Audit Report](./docs/audit-report.md) | Security audit results |

---

## Development

```bash
cd reference/python
pip install -e ".[dev,storage]"
make test          # 350 tests, 100% coverage
make lint          # ruff check
make typecheck     # mypy strict
make test-golden   # Conformance tests only
make test-all      # lint + typecheck + test + golden
```

---

## License

[Apache License 2.0](../../LICENSE) with [additional patent grant](../../PATENTS.md).
