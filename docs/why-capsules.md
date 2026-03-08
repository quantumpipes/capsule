# Why Capsules

> **AI systems need a memory layer that is cryptographically verifiable, tamper-evident, and independent of any single language, framework, or vendor.**

---

## The Problem

AI agents are making autonomous decisions at scale — deploying code, processing financial data, managing infrastructure, generating content. These systems produce thousands of decisions per hour, but the audit trail for those decisions is typically:

- **Application logs** — unstructured, mutable, trivially forgeable
- **Database records** — modifiable by anyone with write access
- **Observability data** — designed for debugging, not for legal evidence

When something goes wrong — a deployment fails, a financial decision is questioned, a regulator asks "why did the AI do that?" — the organization needs evidence that existed *before the question was asked*. Logs can be edited. Database records can be updated. Observability data rotates.

None of these are evidence. They are records of what someone claims happened.

## What Makes Capsules Different

### 1. Pre-Execution Reasoning Capture

The Reasoning section (Section 3) is populated *before* the Execution section (Section 5). This captures the AI's analysis, the options it considered, the option it selected, and why it rejected alternatives — as contemporaneous evidence of deliberation.

This has legal and compliance significance: pre-execution reasoning is stronger evidence than post-hoc explanation. It demonstrates that the system *considered* alternatives before acting, not that it *rationalized* after the fact.

### 2. Cryptographic Tamper Evidence

Every Capsule is hashed with SHA3-256 and signed with Ed25519 at the moment of creation. This is not a property of the storage layer — it is a property of every individual record.

- Modify the content → hash changes → signature invalid
- Delete a record → chain breaks at the gap
- Insert a record → previous_hash mismatch
- Reorder records → sequence numbers mismatch

An attacker who compromises the storage system cannot silently alter the audit trail without invalidating the cryptographic proofs.

### 3. Language-Agnostic Protocol

The Capsule Protocol Specification defines byte-level serialization rules with 16 golden test vectors. A Capsule sealed in Python can be verified in TypeScript, Go, or Rust. This means:

- The audit trail is not locked to a single technology stack
- Verification can happen independently of the system that created the record
- Third parties can verify without running the original code

### 4. Content Addressability

Every Capsule is addressable by its SHA3-256 hash via the `capsule://` URI scheme. This enables cross-system citation, regulatory evidence linking, and a verifiable web of AI decisions.

---

## Who Needs This

| Audience | Why Capsules Matter |
|---|---|
| **CISOs and Security Teams** | Tamper-evident audit trail with FIPS-standard cryptography |
| **Compliance and GRC** | Maps to NIST SP 800-53, AI RMF, EU AI Act, SOC 2, ISO 27001 |
| **Engineering Teams** | Drop-in audit trail that doesn't require changing application architecture |
| **AI Platform Teams** | Protocol-level interoperability across languages, frameworks, and services |
| **Regulators** | Verifiable evidence of AI decision-making with pre-execution reasoning |

---

## Comparison

| Property | Application Logs | Database Records | Capsules |
|---|---|---|---|
| Tamper evidence | None | None | SHA3-256 + Ed25519 |
| Pre-execution reasoning | Rarely captured | Application-dependent | Mandatory (Section 3) |
| Chain integrity | None | None | Hash chain |
| Cross-language verification | N/A | N/A | 16 golden test vectors |
| Content addressable | No | By primary key | By SHA3-256 hash (`capsule://`) |
| Regulatory mapping | Manual | Manual | Built-in (NIST, EU AI Act, SOC 2) |

---

## Related

- [Architecture](./architecture.md) — How the protocol works
- [Security Evaluation](./security.md) — Cryptographic guarantees
- [Compliance Mapping](./compliance.md) — Regulatory framework alignment
- [CPS Specification](../spec/) — The full protocol specification
