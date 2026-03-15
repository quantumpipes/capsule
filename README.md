<div align="center">

# Capsule Protocol

**The cryptographically signed memory layer for autonomous AI.**

Every AI action produces a Capsule — a tamper-evident, content-addressable record of what happened, why it happened, who approved it, and what the outcome was. Sealed with SHA3-256 and Ed25519. Chained for temporal integrity. Verifiable in any language.

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![CPS](https://img.shields.io/badge/CPS-v1.0-orange.svg)](./spec/)
[![Conformance](https://img.shields.io/badge/Conformance-16_vectors-ff69b4.svg)](./conformance/)
[![FIPS](https://img.shields.io/badge/Crypto-FIPS_202%20·%20186--5%20·%20204-purple.svg)](#cryptographic-seal)
[![Coverage](https://img.shields.io/badge/Coverage-100%25-brightgreen.svg)](./reference/python/)

</div>

---

## The Protocol

A Capsule is a cryptographically sealed record of a single AI action. It captures the complete audit trail through six mandatory sections:

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

Every Capsule is hashed with SHA3-256 and signed with Ed25519. Each records the hash of the previous one, forming a chain where tampering with any record invalidates every record that follows.

```
∀ action: ∃ capsule
"For every action, there exists a Capsule."
```

---

## Why Capsules

AI systems make thousands of autonomous decisions. When something goes wrong — or when a regulator asks "why did the AI do that?" — you need evidence that existed *before* the question was asked.

Capsules solve three problems that logging does not:

**1. Pre-execution reasoning capture.**
Section 3 (Reasoning) records the AI's analysis, the options it considered, the option it selected, and why it rejected the alternatives — all captured *before* Section 5 (Execution) runs. This is contemporaneous evidence of deliberation, not a post-hoc reconstruction.

**2. Cryptographic tamper evidence.**
Every Capsule is hashed and signed at the moment of creation. If anyone modifies the content after the fact, the hash changes, the signature fails, and the chain breaks. This is a property of every individual record, not the storage layer.

**3. Cross-language interoperability.**
The Capsule Protocol Specification defines byte-level serialization rules. A Capsule sealed in Python can be verified in TypeScript, Go, or Rust. All implementations produce identical canonical JSON for the same input, validated by 16 golden test vectors.

---

## Content Addressability

Every sealed Capsule is addressable by its SHA3-256 hash via the `capsule://` URI scheme:

```
capsule://sha3_4cb02d65a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef12
```

The hash in the URI is the verification. Obtain the content from any source, recompute the hash, and confirm authenticity. No registry required.

Agents can cite other agents' decisions. Compliance reports can reference specific records. Audit trails become a web of verifiable, linked evidence.

```
capsule://sha3_C  →  previous_hash  →  capsule://sha3_B  →  previous_hash  →  capsule://sha3_A
```

See [URI Scheme specification](./spec/uri-scheme.md).

---

## The Hash Chain

Each Capsule records the SHA3-256 hash of the previous Capsule. This creates a chain where modifying, deleting, or inserting any record is immediately detectable.

```
Capsule #0          Capsule #1          Capsule #2
┌──────────┐        ┌──────────┐        ┌──────────┐
│ hash: A  │◀───────│ prev: A  │◀───────│ prev: B  │
│ prev: ∅  │        │ hash: B  │        │ hash: C  │
└──────────┘        └──────────┘        └──────────┘
```

No consensus mechanism. No distributed ledger. SHA3-256 hashes linking one record to the next.

---

## Cryptographic Seal

Every Capsule is sealed with a two-tier cryptographic architecture:

| Layer | Algorithm | Standard | Purpose |
|---|---|---|---|
| Content integrity | SHA3-256 | FIPS 202 | Tamper-evident hashing |
| Classical signature | Ed25519 | RFC 8032 / FIPS 186-5 | Authenticity and non-repudiation |
| Post-quantum signature | ML-DSA-65 | FIPS 204 | Quantum-resistant protection (optional) |
| Temporal integrity | Hash chain | CPS v1.0 | Ordering and completeness |

No deprecated cryptography. No runtime network dependencies. Air-gapped operation supported.

---

## Specification

The **Capsule Protocol Specification (CPS)** defines the complete protocol:

| Document | Contents |
|---|---|
| [CPS v1.0](./spec/) | Record structure, canonical serialization, sealing algorithm, hash chain rules |
| [URI Scheme](./spec/uri-scheme.md) | `capsule://` content-addressable references |
| [Conformance Suite](./conformance/) | 16 golden vectors (valid) + 15 negative vectors (invalid) |

The specification is language-agnostic. Any implementation that passes the conformance suite can seal and verify Capsules produced by any other.

---

## Example Capsule

```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "type": "agent",
  "trigger": {
    "source": "deploy-bot",
    "request": "Deploy service v2.4 to production"
  },
  "reasoning": {
    "options_considered": ["Deploy v2.4", "Rollback to v2.3", "Do nothing"],
    "selected_option": "Deploy v2.4",
    "confidence": 0.92
  },
  "authority": { "type": "human_approved", "approver": "ops-lead" },
  "execution": {
    "tool_calls": [{ "tool": "kubectl_apply", "success": true, "duration_ms": 3200 }]
  },
  "outcome": { "status": "success", "summary": "Deployed v2.4 to prod-us-east" },
  "hash": "4cb02d65...",
  "signature": "a3f8b2c1...",
  "previous_hash": "7d2e9f41...",
  "sequence": 42
}
```

Six sections. Hashed with SHA3-256. Signed with Ed25519. Chained to the previous record. Reasoning captured *before* execution.

See more examples in [`examples/`](./examples/).

---

## Implementations

### Reference Implementations

These live in this repository and define correct behavior for each language.

| Language | Status | Install | Source |
|---|---|---|---|
| **Python** | v1.3.0 — create, seal, verify, chain, store, CLI | `pip install qp-capsule` | [`reference/python/`](./reference/python/) |
| **TypeScript** | v0.0.1 — create, seal, verify, chain | `npm install @quantumpipes/capsule` | [`reference/typescript/`](./reference/typescript/) |

### Ecosystem Libraries

These extend the protocol to new languages and frameworks.

| Library | Purpose | Install | Source |
|---|---|---|---|
| **[capsule-go](https://github.com/quantumpipes/capsule-go)** | Verify Capsules in Go | `go get github.com/quantumpipes/capsule-go` | [quantumpipes/capsule-go](https://github.com/quantumpipes/capsule-go) |
| **[capsule-litellm](https://github.com/quantumpipes/capsule-litellm)** | Automatic audit trail for LiteLLM | `pip install capsule-litellm` | [quantumpipes/capsule-litellm](https://github.com/quantumpipes/capsule-litellm) |
| capsule-rust | Verify Capsules in Rust | — | Planned |

All implementations must pass the [conformance suite](./conformance/). The specification is the source of truth.

```
  Language A (seal)  ──→  Canonical JSON + SHA3-256 + Ed25519  ──→  Language B (verify) ✓
```

### Quick Start (Python)

```bash
pip install qp-capsule
```

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

### Quick Start (Go — Verification)

```bash
go get github.com/quantumpipes/capsule-go
```

```go
import capsule "github.com/quantumpipes/capsule-go"

// Verify a capsule's hash integrity
valid := capsule.VerifyHash(capsuleDict, expectedHash)

// Verify an Ed25519 signature
valid := capsule.VerifySignature(hashHex, signatureHex, publicKeyHex)

// Verify an entire chain (structural + cryptographic)
errs := capsule.VerifyChainFull(sealedCapsules)
```

The Go library is verification-only by design. Seal in any language, verify in Go — infrastructure tooling, CI gates, and audit pipelines can validate Capsules without a full SDK.

### Quick Start (LiteLLM Integration)

```bash
pip install capsule-litellm
```

```python
import litellm
from capsule_litellm import CapsuleLogger

litellm.callbacks = [CapsuleLogger()]

# Every LLM call now produces a sealed Capsule automatically
response = litellm.completion(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Deploy service v2.4"}],
)
```

Two lines of code. Every `litellm.completion()` and `litellm.acompletion()` call produces a sealed, hash-chained Capsule with the model identity, SHA3-256 prompt hash, token metrics, and latency — without touching your application code.

### Quick Start (TypeScript)

```bash
npm install @quantumpipes/capsule
```

```typescript
import { createCapsule, seal, verify, generateKeyPair } from "@quantumpipes/capsule";

const capsule = createCapsule({
  type: "agent",
  trigger: {
    type: "user_request",
    source: "deploy-bot",
    timestamp: new Date().toISOString().replace("Z", "+00:00"),
    request: "Deploy service v2.4 to production",
    correlation_id: null,
    user_id: null,
  },
});

const { privateKey, publicKey } = generateKeyPair();
await seal(capsule, privateKey);
console.log(await verify(capsule, await publicKey)); // true
```

### CLI

The Python package includes a CLI for verification, inspection, and key management:

```bash
capsule verify chain.json                      # Structural verification
capsule verify --full --db capsules.db         # + SHA3-256 recomputation
capsule verify --signatures --json chain.json  # + Ed25519, JSON output
capsule inspect --db capsules.db --seq 47      # Full 6-section display
capsule keys info                              # Epoch history
capsule keys rotate                            # Rotate to new key (no downtime)
capsule hash document.pdf                      # SHA3-256 of any file
```

Exit codes: `0` = pass, `1` = fail, `2` = error. Designed for CI/CD gates: `capsule verify --quiet && deploy`.

See the [Python reference documentation](./reference/python/) for the full guide.

---

## Compliance

Capsule maps to 11 regulatory frameworks at the protocol level. Each mapping documents which controls the protocol satisfies and which require complementary application-level controls.

| Framework | Controls | Focus |
|---|---|---|
| [NIST SP 800-53](./docs/compliance/nist-sp-800-53.md) | AU-2 through AU-12, SC-13, SC-28, SI-7 | Audit, integrity, crypto |
| [NIST AI RMF](./docs/compliance/nist-ai-rmf.md) | GOVERN, MAP, MEASURE, MANAGE | AI risk management |
| [EU AI Act](./docs/compliance/eu-ai-act.md) | Articles 12, 13, 14 | Record-keeping, transparency, oversight |
| [SOC 2](./docs/compliance/soc2.md) | CC6.1, CC7.2, CC7.3, CC7.4, CC8.1 | Trust Services Criteria |
| [ISO 27001](./docs/compliance/iso27001.md) | A.8.15 through A.8.25 | Annex A controls |
| [HIPAA](./docs/compliance/hipaa.md) | §164.308, §164.312 | Security Rule safeguards |
| [GDPR](./docs/compliance/gdpr.md) | Articles 5, 25, 30, 32, 35 | Data protection |
| [PCI DSS](./docs/compliance/pci-dss.md) | Req 10, 11.5, 11.6 | Logging, change detection |
| [FedRAMP](./docs/compliance/fedramp.md) | AU-9(3), AU-10, SI-7, CM-3 | Federal cloud |
| [FINRA](./docs/compliance/finra.md) | SEC 17a-4, REC-2, Rule 3110 | Financial recordkeeping |
| [CMMC](./docs/compliance/cmmc.md) | AU.L2-3.3.x, SC.L2-3.13.x | DoD CUI protection |

See the [compliance overview](./docs/compliance/) for FIPS algorithm details and scope.

---

## Documentation

| Document | Audience |
|---|---|
| [Architecture](./docs/architecture.md) | Developers, Auditors |
| [Security Evaluation](./docs/security.md) | CISOs, Security Teams |
| [Compliance Mapping](./docs/compliance/) | Regulators, GRC |
| [Why Capsules](./docs/why-capsules.md) | Decision-Makers, Architects |
| [Implementor's Guide](./docs/implementors-guide.md) | SDK Authors |
| [CLI Reference](./docs/architecture.md#cli) | DevOps, Auditors |

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Protocol changes go through the [CPS change proposal](https://github.com/quantumpipes/capsule/issues/new?template=spec-change.md) process. Implementation contributions are welcome in any language.

## License and Patents

[Apache License 2.0](./LICENSE) with [additional patent grant](./PATENTS.md). You can use all patented innovations freely for any purpose, including commercial use.

---

<div align="center">

**∀ action: ∃ capsule**

An open protocol · [Python](./reference/python/) · [TypeScript](./reference/typescript/) · [Go](https://github.com/quantumpipes/capsule-go) · [LiteLLM](https://github.com/quantumpipes/capsule-litellm) · [Conformance suite](./conformance/) for any language

[Specification](./spec/) · [Conformance](./conformance/) · [Security Policy](./SECURITY.md) · [Patent Grant](./PATENTS.md)

Copyright 2026 [Quantum Pipes Technologies, LLC](https://quantumpipes.com)

</div>
