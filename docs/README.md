# Documentation

## Protocol Documentation

These documents explain the Capsule Protocol — why it exists, how it works, and how it maps to regulatory frameworks. They are language-agnostic.

| Document | Audience | Description |
|---|---|---|
| [Why Capsules](./why-capsules.md) | Decision-Makers, Architects | The case for cryptographic AI memory |
| [Architecture](./architecture.md) | Developers, Auditors | 6-section model, sealing, hash chain |
| [Security Evaluation](./security.md) | CISOs, Security Teams | Cryptographic guarantees and key management |
| [Compliance Mapping](./compliance/) | Regulators, GRC | NIST, EU AI Act, SOC 2, ISO 27001, HIPAA, GDPR |
| [Implementor's Guide](./implementors-guide.md) | SDK Authors | How to build a conformant implementation |

## Normative Specification

The protocol specification and conformance suite are the authoritative source of truth:

| Document | Description |
|---|---|
| [CPS v1.0 Specification](../spec/) | Record structure, serialization, sealing, chain rules |
| [URI Scheme](../spec/uri-scheme.md) | `capsule://` content-addressable references |
| [Conformance Suite](../conformance/) | 16 golden test vectors |

## Implementation Documentation

Each reference implementation has its own documentation:

| Language | Docs |
|---|---|
| [Python](../reference/python/docs/) | API reference, getting started, high-level API |
| [TypeScript](../reference/typescript/) | README with API reference, quick start, conformance status |

## Ecosystem Libraries

These extend the protocol to additional languages and frameworks. Each lives in its own repository.

| Library | What It Does | Repository |
|---|---|---|
| **capsule-go** | Verify Capsules in Go. Canonical JSON serialization, SHA3-256 hashing, Ed25519 signature verification, and structural/cryptographic chain verification. Passes all 16 golden vectors. Verification-only by design — seal in any language, verify in Go. | [quantumpipes/capsule-go](https://github.com/quantumpipes/capsule-go) |
| **capsule-litellm** | Automatic Capsule creation for every LLM call through LiteLLM. Two lines to add. Captures model identity, SHA3-256 prompt hash (not the prompt itself), token counts, latency, and errors. Sync and async. | [quantumpipes/capsule-litellm](https://github.com/quantumpipes/capsule-litellm) |
