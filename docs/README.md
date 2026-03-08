# Documentation

## Protocol Documentation

These documents explain the Capsule Protocol — why it exists, how it works, and how it maps to regulatory frameworks. They are language-agnostic.

| Document | Audience | Description |
|---|---|---|
| [Why Capsules](./why-capsules.md) | Decision-Makers, Architects | The case for cryptographic AI memory |
| [Architecture](./architecture.md) | Developers, Auditors | 6-section model, sealing, hash chain |
| [Security Evaluation](./security.md) | CISOs, Security Teams | Cryptographic guarantees and key management |
| [Compliance Mapping](./compliance.md) | Regulators, GRC | NIST, EU AI Act, SOC 2, ISO 27001 |
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
