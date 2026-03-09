---
title: "Getting Started with Capsule"
description: "Create, seal, verify, and chain your first Capsule in under 60 seconds."
date_modified: "2026-03-09"
ai_context: |
  Developer quickstart for the qp-capsule Python package. Covers install,
  creating a Capsule with 6 sections, sealing with Ed25519, verification,
  and hash chain usage. All code examples are complete and runnable.
---

# Getting Started

> **Zero to sealed Capsule in 60 seconds.**

---

## Install

```bash
pip install qp-capsule
```

One dependency: [PyNaCl](https://pynacl.readthedocs.io/) (Ed25519 signatures).

---

## Create and Seal a Capsule

<!-- VERIFIED: reference/python/src/qp_capsule/capsule.py:315-386, reference/python/src/qp_capsule/seal.py:243-300 -->

```python
from qp_capsule import Capsule, Seal, CapsuleType, TriggerSection

capsule = Capsule(
    type=CapsuleType.AGENT,
    trigger=TriggerSection(
        type="user_request",
        source="deploy-bot",
        request="Deploy service v2.4 to production",
    ),
)

seal = Seal()
seal.seal(capsule)

assert seal.verify(capsule)
print(f"Sealed: {capsule.hash[:16]}...")
```

That's it. The Capsule is hashed with SHA3-256 and signed with Ed25519.

---

## Add a Hash Chain

Install with storage support:

```bash
pip install qp-capsule[storage]
```

<!-- VERIFIED: reference/python/src/qp_capsule/chain.py:199-211 -->

```python
from qp_capsule import (
    Capsule, Seal, CapsuleChain, CapsuleStorage,
    CapsuleType, TriggerSection,
)

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
print(f"Chain length: {result.capsules_verified}")
```

Each Capsule records the hash of the one before it. Modify, delete, or insert any record and the chain breaks.

---

## Install Tiers

| Command | What You Get | Dependencies |
|---|---|---|
| `pip install qp-capsule` | Create, seal, verify | 1 (pynacl) |
| `pip install qp-capsule[storage]` | + Hash chain + SQLite | 2 (+ sqlalchemy) |
| `pip install qp-capsule[postgres]` | + Hash chain + PostgreSQL | 2 (+ sqlalchemy) |
| `pip install qp-capsule[pq]` | + Post-quantum ML-DSA-65 | 2 (+ liboqs) |

---

## The 6 Sections

Every Capsule has six sections. Together they form a complete record of a single action:

<!-- VERIFIED: reference/python/src/qp_capsule/capsule.py:78-307 -->

```python
from qp_capsule import (
    Capsule, CapsuleType,
    TriggerSection, ContextSection, ReasoningSection,
    AuthoritySection, ExecutionSection, OutcomeSection, ToolCall,
)

capsule = Capsule(
    type=CapsuleType.AGENT,

    # 1. What initiated this action?
    trigger=TriggerSection(
        type="user_request",
        source="ops-team",
        request="Scale web tier to 6 replicas",
    ),

    # 2. What was the state of the system?
    context=ContextSection(
        agent_id="infra-agent",
        session_id="sess-abc-123",
        environment={"cluster": "prod-us-east"},
    ),

    # 3. Why was this decision made? (captured BEFORE execution)
    reasoning=ReasoningSection(
        analysis="Current load is 82%, approaching threshold",
        options_considered=["Scale to 6", "Scale to 8", "Do nothing"],
        selected_option="Scale to 6",
        reasoning="6 replicas handles projected load with 30% headroom",
        confidence=0.92,
    ),

    # 4. Who approved it?
    authority=AuthoritySection(
        type="policy",
        policy_reference="AUTO-SCALE-001",
    ),

    # 5. What tools were called?
    execution=ExecutionSection(
        tool_calls=[
            ToolCall(
                tool="kubectl_scale",
                arguments={"replicas": 6},
                result={"status": "scaled"},
                success=True,
                duration_ms=3200,
            ),
        ],
        duration_ms=3200,
    ),

    # 6. What was the result?
    outcome=OutcomeSection(
        status="success",
        summary="Scaled web tier to 6 replicas",
        side_effects=["deployment/web replicas: 4 -> 6"],
    ),
)
```

Reasoning is captured **before** execution. This provides contemporaneous evidence of deliberation, not post-hoc justification.

---

## Tamper Detection

This is what makes Capsule different from logging. Seal a Capsule, tamper with it, and watch verification catch it:

<!-- VERIFIED: reference/python/src/qp_capsule/seal.py:338-385 -->

```python
from qp_capsule import Capsule, Seal, CapsuleType, TriggerSection

capsule = Capsule(
    type=CapsuleType.AGENT,
    trigger=TriggerSection(source="test", request="Original request"),
)

seal = Seal()
seal.seal(capsule)

# Verification passes
assert seal.verify(capsule)
print("Before tampering: VALID")

# Now tamper with the content
capsule.trigger.request = "Altered request"

# Verification FAILS — the hash no longer matches the content
assert not seal.verify(capsule)
print("After tampering:  INVALID — tamper detected")
```

**Expected output:**

```
Before tampering: VALID
After tampering:  INVALID — tamper detected
```

The hash was computed from the original content. When the content changed, the hash no longer matched. No log rotation, no admin privilege, no database access can make a tampered Capsule pass verification.

---

## High-Level API (v1.1.0+)

For most integrations, the high-level API is the fastest path. One class, one decorator:

```bash
pip install qp-capsule[storage]
```

<!-- VERIFIED: reference/python/src/qp_capsule/audit.py:130-216 -->

```python
from qp_capsule import Capsules

capsules = Capsules()

@capsules.audit(type="agent")
async def run_agent(task: str):
    cap = capsules.current()
    cap.reasoning.model = "gpt-4o"
    cap.reasoning.confidence = 0.92
    result = await llm.complete(task)
    cap.outcome.summary = f"Generated {len(result.text)} chars"
    return result

await run_agent("Write a summary of Q1 results")
```

The decorator handles Capsule creation, sealing, chaining, and storage automatically. If capsule creation fails, your function still works normally.

See [High-Level API](./high-level-api.md) for the full guide.

---

## CLI (v1.3.0+)

The package installs a `capsule` command for verification, inspection, and key management:

```bash
capsule verify chain.json                      # Structural verification
capsule verify --full --db ~/.quantumpipes/capsules.db  # + SHA3-256
capsule inspect --db capsules.db --seq 42      # Show capsule #42
capsule keys info                              # Key epoch history
capsule keys rotate                            # Rotate to new key
capsule hash document.pdf                      # SHA3-256 of any file
```

Use `capsule verify --quiet && deploy` as a CI/CD gate. Exit code `0` means the chain is intact.

---

## What's Next

- [High-Level API](./high-level-api.md) — `Capsules`, `@audit`, `current()`, FastAPI integration
- [API Reference](./api.md) — Every class, method, and parameter
- [Architecture](../../../docs/architecture.md) — Deep dive on the 6-section model, cryptographic sealing, and hash chain
- [Security Evaluation](../../../docs/security.md) — Cryptographic guarantees for security teams
- [CPS Specification](../../../spec/) — The normative protocol spec

---

*For every action, there exists a Capsule.*
