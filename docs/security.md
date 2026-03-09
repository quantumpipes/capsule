---
title: "Security Evaluation Guide"
description: "Security evaluation guide for CISOs and security teams assessing Capsule for organizational adoption. Covers cryptographic architecture, key management, tamper evidence, attack surface, and deployment."
date_modified: "2026-03-09"
classification: "Public"
ai_context: |
  CISO-targeted security evaluation of the Capsule package. Covers two-tier
  crypto (SHA3-256 + Ed25519 + optional ML-DSA-65), key management (file-based,
  0600 permissions, auto-generated), tamper evidence (hash chain breaks on any
  modification), dependency audit (1 required dep), air-gapped operation,
  attack surface analysis, and evaluation checklist.
---

# Security Evaluation Guide

**For CISOs and Security Teams Evaluating Capsule**

*Capsule v1.3.0 — March 2026*
*Classification: Public*

---

## 1. Executive Summary

Capsule is a cryptographic audit record for AI operations. Every AI action produces a sealed, tamper-evident record signed with Ed25519 and optionally with the NIST-standardized post-quantum algorithm ML-DSA-65 (FIPS 204). Records are linked into a hash chain where modifying any single record invalidates every record that follows.

**The security proposition in three sentences:**

1. Every AI action is recorded with six auditable sections captured at the moment of action, including reasoning captured *before* execution.
2. Records are hashed with SHA3-256 (FIPS 202) and signed with Ed25519 (FIPS 186-5), with optional quantum-resistant ML-DSA-65 (FIPS 204) dual signatures.
3. A hash chain links each record to the previous one; tampering with any record breaks the chain and is immediately detectable.

---

## 2. Cryptographic Architecture

<!-- VERIFIED: reference/python/src/qp_capsule/seal.py:7-30, 243-300 -->

### Algorithm Selection

| Layer | Algorithm | Standard | Purpose | Why This Algorithm |
|---|---|---|---|---|
| Content integrity | SHA3-256 | FIPS 202 | Tamper-evident hashing | Resistant to length-extension attacks (unlike SHA-256) |
| Classical signature | Ed25519 | RFC 8032 / FIPS 186-5 | Authenticity and non-repudiation | OWASP/IETF recommended; default in OpenSSH |
| Post-quantum signature | ML-DSA-65 | FIPS 204 | Quantum-resistant protection | NIST Level 3 (~AES-192); finalized August 2024 |
| Temporal integrity | Hash chain | CPS v1.0 | Ordering and completeness | No consensus mechanism or distributed ledger required |

### Two-Tier Model

- **Tier 1 (default):** SHA3-256 + Ed25519. Available on all platforms via PyNaCl. No additional dependencies.
- **Tier 2 (with `[pq]`):** Everything in Tier 1, plus ML-DSA-65 dual signatures. Requires `liboqs-python`.

Ed25519 is always required. ML-DSA-65 is additive, never a replacement. If one algorithm is compromised, the other still provides protection.

### Sealing Process

1. Capsule content serialized to canonical JSON (sorted keys, compact separators)
2. SHA3-256 hash computed over UTF-8 encoded canonical JSON
3. Ed25519 signature computed over the hex-encoded hash
4. ML-DSA-65 signature computed over the hex-encoded hash (if enabled)
5. Hash, signature(s), timestamp, and key fingerprint stored on the Capsule

### No Deprecated Cryptography

| Algorithm | Status |
|---|---|
| SHA-1 | Not used |
| MD5 | Not used |
| RSA | Not used |
| AES-CBC | Not used |
| Dilithium3 (legacy name) | Removed; replaced by ML-DSA-65 (FIPS 204 standardized name) |

---

## 3. Key Management

<!-- VERIFIED: reference/python/src/qp_capsule/seal.py:50-55, 122-159, 161-222 -->

### Storage Locations

| Key | Default Path | Permissions | Override |
|---|---|---|---|
| Ed25519 private key | `~/.quantumpipes/key` | `0600` | `QUANTUMPIPES_DATA_DIR` env var or `key_path` parameter |
| ML-DSA-65 secret key | `~/.quantumpipes/key.ml` | `0600` | Same directory as Ed25519 key |
| ML-DSA-65 public key | `~/.quantumpipes/key.ml.pub` | `0644` | Same directory as Ed25519 key |

### Generation

- Keys are generated automatically on first use using cryptographically secure random sources
- File creation uses `os.umask(0o077)` before writing to prevent race conditions between creation and permission setting
- Permissions are enforced with both umask (at creation) and explicit `chmod` (belt and suspenders)
- No external key management service is required for basic operation

### Key Rotation

<!-- VERIFIED: reference/python/src/qp_capsule/keyring.py:226-271 -->

Key rotation is automated through the epoch-based keyring system, aligned with NIST SP 800-57:

```bash
capsule keys rotate    # Generate new key, retire current, update keyring. No downtime.
```

Rotation protocol:

1. Generate new Ed25519 key pair using cryptographically secure random
2. Set current epoch's status to `retired` with timestamp
3. Add new epoch as `active`
4. Write new private key to disk (securely replaces old)
5. Save keyring atomically (temp file + `os.replace`)

**Backward compatibility:** After rotation, Capsules signed with previous keys continue to verify. The keyring retains all retired epochs' public keys. `Seal.verify()` uses the capsule's `signed_by` fingerprint to look up the correct epoch's public key automatically.

**Migration:** Existing installations without a keyring file are migrated seamlessly. On first use, the Seal or CLI creates `keyring.json` with epoch 0 for the existing key. No manual intervention required.

**Automated rotation:** Schedule `capsule keys rotate` via cron for periodic rotation (e.g., every 90 days).

> **Note:** HSM integration is planned for a future release. File-based key storage is appropriate for development and single-tenant deployments. For multi-tenant production deployments, ensure key directories have appropriate OS-level access controls.

---

## 4. Tamper Evidence

### What Capsule Detects

| Attack | Detection Mechanism | Verification Method |
|---|---|---|
| Content modification | SHA3-256 hash changes; Ed25519 signature fails | `seal.verify(capsule)` returns `False` |
| Record deletion | Sequence gap (expected N, got N+2) | `chain.verify()` returns `broken_at` |
| Record insertion | `previous_hash` mismatch at insertion point | `chain.verify()` returns `broken_at` |
| Record reordering | Sequence and `previous_hash` mismatches | `chain.verify()` returns `broken_at` |
| Genesis tampering | Genesis Capsule has `previous_hash` set (should be `None`) | `chain.verify()` returns error |
| Signature forgery | Ed25519 verification fails against stored public key | `seal.verify(capsule)` returns `False` |

### What Capsule Does NOT Protect Against

| Threat | Why | Mitigation |
|---|---|---|
| Private key compromise | Attacker with the signing key can forge valid signatures | Restrict key file permissions; use HSM in production; rotate keys |
| Side-channel attacks on key material | File-based storage is vulnerable to timing/cache attacks | Use HSM for key operations in high-security environments |
| Denial of service (preventing record creation) | Capsule cannot force an application to create records | Application-level monitoring; kill switch integration |
| Pre-image attacks on SHA3-256 | Theoretical; no known practical attack exists | SHA3-256 provides 128-bit pre-image resistance |
| Quantum attacks on Ed25519 | Ed25519 is vulnerable to Shor's algorithm (future threat) | Enable ML-DSA-65 dual signatures with `pip install qp-capsule[pq]` |

---

## 5. Dependency Audit

<!-- VERIFIED: pyproject.toml:41-56 -->

### Required Dependencies

| Package | License | Purpose | Version |
|---|---|---|---|
| `pynacl` | Apache 2.0 | Ed25519 signatures (libsodium binding) | >= 1.6.2 |

**Total: 1 required dependency** for the base package.

### Optional Dependencies

| Extra | Package | License | Purpose |
|---|---|---|---|
| `[storage]` | `sqlalchemy`, `aiosqlite` | MIT | SQLite persistence |
| `[postgres]` | `sqlalchemy`, `asyncpg` | MIT | PostgreSQL persistence |
| `[pq]` | `liboqs-python` | MIT | Post-quantum ML-DSA-65 signatures |

### Runtime Network Dependencies

**None.** Capsule has zero runtime network dependencies. All cryptographic operations use local computation. All storage operations use local (SQLite) or configured (PostgreSQL) databases. Capsule operates fully in air-gapped environments.

---

## 6. Deployment Considerations

### Single-Node (SQLite)

- Zero configuration: `CapsuleStorage()` creates the database at `~/.quantumpipes/capsules.db`
- Appropriate for development, testing, and single-tenant deployments
- No network dependencies

### Multi-Tenant (PostgreSQL)

- `PostgresCapsuleStorage("postgresql+asyncpg://...")` with per-tenant isolation
- `tenant_id` parameter on `store()`, `list()`, `get_latest()`, `count()` scopes all operations
- Table: `quantumpipes_capsules` (prefixed to avoid collisions)
- Connection pooling: 5 connections, 10 max overflow

### Air-Gapped Operation

Capsule is designed for air-gapped environments:

- No telemetry or analytics
- No license server or activation
- No external API calls at runtime
- All cryptographic operations use local key material
- SQLite storage requires no network access

---

## 7. Evaluation Checklist

Use this checklist when evaluating Capsule for your organization:

| Criterion | Status | Detail |
|---|---|---|
| Uses NIST-approved hash algorithm | Yes | SHA3-256 (FIPS 202) |
| Uses NIST-approved signature algorithm | Yes | Ed25519 (FIPS 186-5) |
| Post-quantum protection available | Yes | ML-DSA-65 (FIPS 204), optional |
| Private keys protected at rest | Yes | File permissions `0600`, umask-based creation |
| Tamper detection for individual records | Yes | Hash + signature verification |
| Tamper detection for record sequence | Yes | Hash chain with sequence numbers |
| Minimal dependency footprint | Yes | 1 required dependency (pynacl) |
| Air-gapped operation | Yes | Zero network dependencies at runtime |
| Open source with patent grant | Yes | Apache 2.0 + additional patent grant |
| Cross-language verification | Partial | Python SDK (available); TypeScript, Go, Rust (planned). CPS spec + 16 golden test vectors published for cross-language conformance. |
| Audit trail immutability | Yes | Hash chain; any modification breaks the chain |
| Pre-execution reasoning capture | Yes | Section 3 (Reasoning) captured before Section 5 (Execution) |
| Multi-tenant isolation | Yes | PostgreSQL backend with `tenant_id` scoping |
| Test coverage | Yes | 100% line coverage enforced in CI (`fail_under = 100`) |
| Warning-free | Yes | `filterwarnings = ["error"]` with zero exemptions |
| Key rotation support | Yes | Automated via `capsule keys rotate`; epoch-based keyring with backward-compatible verification; HSM planned |
| FIPS 140-2/3 validated module | No | Uses FIPS-approved algorithms via PyNaCl/libsodium; module itself is not FIPS-validated |

---

## Related Documentation

- [Architecture](./architecture.md) — Technical deep dive on the 6-section model and cryptographic sealing
- [Compliance Mapping](./compliance/) — NIST SP 800-53, EU AI Act, SOC 2, ISO 27001, HIPAA, GDPR
- [CPS Specification](../spec/) — Protocol rules and golden test vectors
- [SECURITY.md](../SECURITY.md) — Vulnerability reporting

---

*Capsule v1.3.0 — Quantum Pipes Technologies, LLC*
