---
title: "Regulatory Compliance Mapping"
description: "How Capsule maps to NIST SP 800-53, NIST AI RMF, EU AI Act, SOC 2, and ISO 27001 controls."
date_modified: "2026-03-07"
classification: "Public"
ai_context: |
  Compliance mapping for Capsule across major regulatory frameworks.
  Covers NIST SP 800-53 (AU, SC, SI families), NIST AI RMF (GOVERN, MAP,
  MEASURE, MANAGE), EU AI Act (Articles 12, 13, 14), SOC 2 Trust Services
  Criteria, ISO 27001, and FIPS algorithm compliance. Each mapping identifies
  the specific Capsule capability that addresses the control.
---

# Regulatory Compliance Mapping

> **How Capsule maps to the frameworks your auditors care about.**

*Capsule v1.0.0 — March 2026*
*Classification: Public*

---

## FIPS Algorithm Compliance

Before mapping to controls, the foundational question: are the cryptographic algorithms standards-compliant?

| Algorithm | FIPS Standard | Status | Capsule Usage |
|---|---|---|---|
| SHA3-256 | FIPS 202 (SHA-3) | Published August 2015 | Content hashing for every Capsule |
| Ed25519 | FIPS 186-5 (Digital Signatures) | Published February 2023 | Required signature on every Capsule |
| ML-DSA-65 | FIPS 204 (ML-DSA) | Published August 2024 | Optional post-quantum dual signature |

All three algorithms are NIST-standardized. No deprecated or non-standard cryptography is used.

---

## NIST SP 800-53 Rev. 5

Security and privacy controls for information systems. Capsule addresses controls in the Audit (AU), System and Communications Protection (SC), and System and Information Integrity (SI) families.

### Audit and Accountability (AU)

| Control | Title | How Capsule Addresses It |
|---|---|---|
| **AU-2** | Event Logging | Every AI action produces a Capsule. The `CapsuleType` enum defines 8 event categories: agent, tool, system, kill, workflow, chat, vault, auth. |
| **AU-3** | Content of Audit Records | Each Capsule contains 6 sections: Trigger (who/what/when), Context (system state), Reasoning (why), Authority (approval), Execution (how), Outcome (result). |
| **AU-3(1)** | Additional Audit Information | `correlation_id` links related Capsules across distributed operations. `parent_id` creates hierarchical relationships. `session_id` groups conversation turns. |
| **AU-8** | Time Stamps | `trigger.timestamp` records UTC time of action initiation. `signed_at` records UTC time of cryptographic sealing. Both are timezone-aware. |
| **AU-9** | Protection of Audit Information | SHA3-256 hash + Ed25519 signature prevents undetected modification. Hash chain prevents undetected deletion or insertion. |
| **AU-10** | Non-repudiation | Ed25519 digital signatures provide non-repudiation via `signed_by` (key fingerprint). `verify_with_key()` enables third-party verification. |
| **AU-11** | Audit Record Retention | Capsules are persisted in SQLite or PostgreSQL. Retention policies are configurable at the storage layer. |
| **AU-12** | Audit Record Generation | Capsule creation is application-initiated at the moment of action. The `seal_and_store()` convenience method ensures atomic chain + seal + store. |

### System and Communications Protection (SC)

| Control | Title | How Capsule Addresses It |
|---|---|---|
| **SC-13** | Cryptographic Protection | SHA3-256 (FIPS 202) for integrity, Ed25519 (FIPS 186-5) for signatures, ML-DSA-65 (FIPS 204) for quantum resistance. |
| **SC-28** | Protection of Information at Rest | Sealed Capsules are integrity-protected via cryptographic signatures. Storage-level encryption is configurable at the database layer. |

### System and Information Integrity (SI)

| Control | Title | How Capsule Addresses It |
|---|---|---|
| **SI-7** | Software, Firmware, and Information Integrity | `chain.verify()` detects any modification, deletion, or insertion in the audit trail. |
| **SI-7(1)** | Integrity Checks | Verification can run anytime: `seal.verify(capsule)` for individual records, `chain.verify()` for the entire chain. |

---

## NIST AI Risk Management Framework (AI RMF 1.0)

The AI RMF organizes AI risk management into four functions: GOVERN, MAP, MEASURE, MANAGE.

### GOVERN

*Cultivate and implement a culture of AI risk management.*

| Practice | How Capsule Supports It |
|---|---|
| Establish accountability structures | Authority section records who approved each action (`autonomous`, `human_approved`, `policy`, `escalated`) |
| Document AI decision-making processes | Reasoning section captures analysis, options considered, selected option, and confidence before execution |
| Maintain audit trails | Hash-chained Capsules provide an immutable, tamper-evident record of every AI action |

### MAP

*Contextualize AI risks.*

| Practice | How Capsule Supports It |
|---|---|
| Identify AI system components | Capsule Types map to system components: AGENT, TOOL, WORKFLOW, CHAT, VAULT |
| Document operating context | Context section records agent_id, session_id, and environment state at time of action |
| Track data lineage | Execution section records tool calls with arguments, results, and errors |

### MEASURE

*Analyze, assess, and track AI risks.*

| Practice | How Capsule Supports It |
|---|---|
| Quantify model confidence | `reasoning.confidence` (0.0 to 1.0) records model-reported confidence per action |
| Track performance metrics | `outcome.metrics` captures duration, token usage, cost, and custom metrics |
| Monitor for anomalies | `outcome.status` values (`success`, `failure`, `partial`, `blocked`) enable monitoring |

### MANAGE

*Prioritize and act on AI risks.*

| Practice | How Capsule Supports It |
|---|---|
| Implement kill switches | `CapsuleType.KILL` records kill switch activations with authority chain |
| Enable human oversight | Authority section's `escalation_reason` and `approver` fields document human-in-the-loop decisions |
| Verify system integrity | `chain.verify()` provides one-call integrity verification of the entire audit trail |

---

## EU AI Act

The EU AI Act (Regulation 2024/1689) establishes requirements for AI systems operating in the EU.

### Article 12: Record-keeping

*High-risk AI systems shall be designed with logging capabilities that record events relevant to the functioning of the AI system.*

| Requirement | How Capsule Addresses It |
|---|---|
| Automatic logging of events | Every AI action produces a Capsule (the axiom: for all actions, there exists a Capsule) |
| Traceability of results | Execution section records tool calls; Outcome section records results and side effects |
| Monitoring of operation | Chain provides temporal ordering; session_id groups related interactions |
| Identification of risks | Reasoning section captures risk assessment in `ReasoningOption.risks` |

### Article 13: Transparency

*High-risk AI systems shall be designed to ensure their operation is sufficiently transparent.*

| Requirement | How Capsule Addresses It |
|---|---|
| Understandable output | Outcome section includes human-readable `summary` field |
| Explanation of decisions | Reasoning section captures analysis, options, and rationale *before* execution |
| Information for deployers | Capsules are queryable via storage backends; all fields are machine-readable |

### Article 14: Human Oversight

*High-risk AI systems shall be designed to be effectively overseen by natural persons.*

| Requirement | How Capsule Addresses It |
|---|---|
| Human-in-the-loop capability | Authority section supports `human_approved` type with `approver` identity |
| Ability to intervene | Kill switch Capsules (`CapsuleType.KILL`) record intervention events |
| Override capability | Authority section's `escalation_reason` documents why human override occurred |

---

## SOC 2 Trust Services Criteria

SOC 2 Type II audit mappings for the Security and Availability trust service categories.

| Criterion | Title | How Capsule Addresses It |
|---|---|---|
| **CC6.1** | Logical access security | Ed25519 key-based signing; key files restricted to owner (0600 permissions) |
| **CC7.2** | System monitoring | Every AI action produces a Capsule; chain provides complete operational history |
| **CC7.3** | Detection of unauthorized changes | `chain.verify()` detects any modification, deletion, or insertion |
| **CC7.4** | Incident response data | Capsules contain full context (6 sections) for post-incident analysis |
| **CC8.1** | Change management | Each Capsule records what changed (`outcome.side_effects`), who approved it (`authority`), and why (`reasoning`) |

---

## ISO 27001:2022

Selected controls from Annex A.

| Control | Title | How Capsule Addresses It |
|---|---|---|
| **A.8.15** | Logging | Every AI action produces a Capsule with 6 auditable sections |
| **A.8.16** | Monitoring activities | Chain provides temporal ordering; `type_filter` enables monitoring by event category |
| **A.8.17** | Clock synchronization | `trigger.timestamp` and `signed_at` use timezone-aware UTC |
| **A.8.24** | Use of cryptography | SHA3-256 (FIPS 202), Ed25519 (FIPS 186-5), ML-DSA-65 (FIPS 204) |
| **A.8.25** | Secure development lifecycle | 350 automated tests with 100% coverage; strict mypy; ruff linting; `filterwarnings = ["error"]` |

---

## Cross-Language Conformance

Capsule sealed in any language can be verified in any other. The Capsule Protocol Specification (CPS) defines:

- Byte-level canonical JSON serialization rules
- 16 golden test vectors covering all CapsuleTypes, Unicode, fractional timestamps, chain sequences, empty vs null, deep nesting, and failure paths
- SHA3-256 hash determinism across implementations

The Python reference implementation is available now. Cross-language SDKs (TypeScript, Go, Rust) are planned. All must produce byte-identical canonical JSON and matching SHA3-256 hashes for the golden test vectors.

See [CPS Specification](../spec/) for protocol details.

---

## Related Documentation

- [Security Evaluation](./security.md) — Cryptographic architecture, key management, attack surface
- [Architecture](./architecture.md) — 6-section model, sealing process, hash chain
- [CPS Specification](../spec/) — Protocol rules and golden test vectors

---

*Capsule v1.0.0 — Quantum Pipes Technologies, LLC*
