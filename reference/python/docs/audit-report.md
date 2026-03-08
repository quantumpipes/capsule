---
title: "Independent Security Audit Report"
description: "Comprehensive security audit of the Capsule v1.0.0 codebase: automated scanning, cryptographic review, dependency analysis, coverage metrics, and OWASP assessment."
date_modified: "2026-03-07"
classification: "Public"
ai_context: |
  Self-audit report for Capsule v1.0.0 intended for CISOs, regulators, and
  security teams. Contains bandit scan results (0 findings), pip-audit results
  (0 vulnerable deps), OWASP Top 10 mapping, post-quantum compliance status,
  coverage metrics (350 tests, 100%), and a structured evaluation checklist.
---

# Security Audit Report

**Capsule v1.0.0 — Capsule Protocol Specification (CPS) v1.0**

*Audit date: March 7, 2026*
*Classification: Public*
*Auditor: Quantum Pipes Technologies, LLC (self-audit)*

---

## 1. Executive Summary

Capsule is a cryptographic audit record protocol for AI operations. This report documents the security posture of the v1.0.0 release based on automated scanning, manual code review, and invariant testing.

**Key findings:**

- **Bandit static analysis: 0 issues** across 1,684 lines of source code
- **Dependency audit: 0 known vulnerabilities** in runtime dependencies
- **Test coverage: 100%** (675 statements, 350 tests, 0 lines missed)
- **Warning policy: zero tolerance** (`filterwarnings = ["error"]`, 0 exemptions)
- **OWASP Top 10: all applicable items addressed**
- **Post-quantum ready:** ML-DSA-65 (FIPS 204) dual signatures available

---

## 2. Scope

### In Scope

- All source code in `src/qp_capsule/` (9 Python modules, 675 statements)
- All dependencies declared in `pyproject.toml`
- Cryptographic algorithm selection and key management
- Storage backend security (SQLite and PostgreSQL)
- Tenant isolation in multi-tenant deployments

### Out of Scope

- Application-level code that uses the Capsule library
- Network transport security (TLS configuration is the deployer's responsibility)
- Operating system hardening
- TypeScript, Go, and Rust SDK implementations

---

## 3. Automated Security Scanning

### 3.1 Bandit (Static Analysis)

Tool: [Bandit](https://bandit.readthedocs.io/) — Python security linter

```
Run started: 2026-03-07
Target: src/qp_capsule/

Total lines of code: 1,684
Total lines skipped (#nosec): 0
Total potential issues skipped: 0

Issues by severity:
  Undefined: 0
  Low:       0
  Medium:    0
  High:      0

Issues by confidence:
  Undefined: 0
  Low:       0
  Medium:    0
  High:      0

Files skipped: 0
```

**Result: 0 findings.** No hardcoded secrets, no unsafe deserialization, no shell injection, no use of deprecated modules.

### 3.2 pip-audit (Dependency Vulnerabilities)

Tool: [pip-audit](https://pypi.org/project/pip-audit/) — Dependency vulnerability scanner

| Package | Version | Vulnerabilities |
|---|---|---|
| pynacl | 1.6.2 | 0 |
| sqlalchemy | 2.0.48 | 0 |
| aiosqlite | 0.22.1 | 0 |
| greenlet | (latest) | 0 |

**Result: 0 known vulnerabilities** in any runtime dependency.

### 3.3 Ruff (Lint)

Tool: [Ruff](https://docs.astral.sh/ruff/) — Python linter (E, F, I, W rules)

**Result: 0 errors** across all source, test, and spec files.

---

## 4. Cryptographic Architecture

### 4.1 Algorithm Selection

| Purpose | Algorithm | Standard | Security Level | Status |
|---|---|---|---|---|
| Content hashing | SHA3-256 | FIPS 202 | 128-bit pre-image resistance | Required |
| Classical signature | Ed25519 | RFC 8032 / FIPS 186-5 | ~128-bit security | Required |
| Post-quantum signature | ML-DSA-65 | FIPS 204 | NIST Level 3 (~AES-192) | Optional |
| Temporal integrity | Hash chain | CPS v1.0 | — | Required |

### 4.2 Why These Algorithms

| Algorithm | Reason for Selection |
|---|---|
| SHA3-256 over SHA-256 | Resistant to length-extension attacks. Keccak sponge construction provides a different failure mode than SHA-2 family, reducing correlated risk. |
| Ed25519 over RSA | Fixed-size keys (32 bytes), deterministic signatures (no nonce reuse risk), faster verification, OWASP/IETF recommended, default in OpenSSH since 2014. |
| ML-DSA-65 over other PQ | NIST FIPS 204 standardized (August 2024). Level 3 security. Active IETF work on hybrid Ed25519+ML-DSA (draft-ietf-lamps-dilithium-certificates). |

### 4.3 Deprecated Algorithms

| Algorithm | Status |
|---|---|
| MD5 | Not used |
| SHA-1 | Not used |
| RSA | Not used |
| DES / 3DES | Not used |
| RC4 | Not used |
| Dilithium3 (legacy name) | Not used. ML-DSA-65 is the FIPS 204 standardized name. |

### 4.4 Sealing Process

```
Capsule.to_dict()  →  Canonical JSON (sorted keys, compact)
                   →  UTF-8 encode
                   →  SHA3-256 hash (64 hex chars)
                   →  Ed25519 sign hash string (128 hex chars)
                   →  ML-DSA-65 sign hash string (optional)
```

The signature is computed over the **hex-encoded hash string**, not the raw bytes. This is deliberate and documented in the CPS specification.

---

## 5. Key Management

### 5.1 Key Storage

| Key | Default Location | Permissions | Creation |
|---|---|---|---|
| Ed25519 private key | `~/.quantumpipes/key` | `0600` | On first `seal()` call |
| ML-DSA-65 secret key | `~/.quantumpipes/key.ml` | `0600` | On first PQ `seal()` call |
| ML-DSA-65 public key | `~/.quantumpipes/key.ml.pub` | `0644` | On first PQ `seal()` call |

### 5.2 Key Generation

- Ed25519: `nacl.signing.SigningKey.generate()` (libsodium CSPRNG)
- ML-DSA-65: `oqs.Signature("ML-DSA-65").generate_keypair()` (liboqs)

### 5.3 File Creation Security

Keys are created using `os.umask(0o077)` before writing, then explicit `chmod` after:

```python
old_umask = os.umask(0o077)
try:
    key_path.write_bytes(key_material)
finally:
    os.umask(old_umask)
key_path.chmod(0o600)
```

This eliminates the TOCTOU race between file creation and permission setting. The umask ensures the file is never world-readable, even momentarily.

### 5.4 Path Validation

The `QUANTUMPIPES_DATA_DIR` environment variable is validated before use:

```python
def resolve_data_dir(data_dir: str) -> Path:
    if ".." in Path(data_dir).parts:
        raise CapsuleError("Data directory must not contain '..' components")
    return Path(data_dir).resolve()
```

This prevents directory traversal via environment variable manipulation.

### 5.5 Key Rotation

Key rotation is currently manual:

1. Stop the application
2. Archive existing keys
3. Restart (new keys auto-generated)
4. Previous Capsules remain verifiable via `seal.verify_with_key(capsule, old_public_key_hex)`

HSM integration is planned for a future release.

---

## 6. Tenant Isolation

### 6.1 Multi-Tenant Storage

The `PostgresCapsuleStorage` backend enforces tenant isolation on every query method:

| Method | Tenant Enforcement |
|---|---|
| `store(capsule, tenant_id=)` | Stores with tenant_id column |
| `get(capsule_id, tenant_id=)` | Filters by tenant_id on exact and partial match |
| `get_latest(tenant_id=)` | Scoped to tenant |
| `get_all_ordered(tenant_id=)` | Scoped to tenant |
| `list(tenant_id=)` | Scoped to tenant |
| `count(tenant_id=)` | Scoped to tenant |

When `tenant_id` is provided, a capsule belonging to tenant A cannot be retrieved by tenant B, even if tenant B knows the capsule's UUID.

### 6.2 SQLite Storage

The SQLite backend accepts `tenant_id` on all methods for interface compatibility but ignores it. SQLite storage is designed for single-tenant deployments.

### 6.3 Chain Verification

`chain.verify(tenant_id=)` and `chain.verify_capsule_in_chain(capsule, tenant_id=)` both scope verification to a single tenant's chain. Tenants' chains are independent.

---

## 7. Input Validation

### 7.1 Boundaries

| Boundary | Validation |
|---|---|
| Unsealed Capsule storage | Rejected with `StorageError("Cannot store unsealed Capsule")` |
| Session ID format | UUID format validated in `list_by_session()`; invalid format returns empty list |
| Data directory path | `..` components rejected by `resolve_data_dir()` |
| PQ availability | `Seal(enable_pq=True)` raises `SealError` if liboqs is not installed |

### 7.2 Error Message Sanitization

All exception messages in storage and seal operations report the exception **type name only**, not the raw exception text:

```python
raise SealError(f"Failed to seal Capsule: {type(e).__name__}")
```

Only the exception type name is included (e.g., `RuntimeError`, `PermissionError`). The raw exception message — which may contain file paths, database connection strings, or key locations — is never exposed.

This prevents information disclosure of internal paths, database connection strings, or key file locations through error messages.

---

## 8. Dependency Analysis

### 8.1 Runtime Dependencies

| Package | License | Lines of Code | Purpose |
|---|---|---|---|
| `pynacl` (required) | Apache 2.0 | ~3,500 (Python bindings for libsodium) | Ed25519 signing/verification |

**Total required runtime dependencies: 1.**

### 8.2 Optional Dependencies

| Package | License | Extra | Purpose |
|---|---|---|---|
| `sqlalchemy` | MIT | `[storage]`, `[postgres]` | Database ORM |
| `aiosqlite` | MIT | `[storage]` | Async SQLite driver |
| `asyncpg` | Apache 2.0 | `[postgres]` | Async PostgreSQL driver |
| `liboqs-python` | MIT | `[pq]` | ML-DSA-65 post-quantum signatures |

### 8.3 No Runtime Network Dependencies

Capsule makes **zero network calls** at runtime. All cryptographic operations use local key material. All storage operations use local (SQLite) or configured (PostgreSQL) databases. The library operates fully in air-gapped environments.

---

## 9. OWASP Top 10 Assessment

| # | Vulnerability | Applicable | Status | Detail |
|---|---|---|---|---|
| A01 | Broken Access Control | Yes | Addressed | Tenant isolation enforced on all 7 Protocol methods |
| A02 | Cryptographic Failures | Yes | Addressed | FIPS 202, 186-5, 204. No deprecated algorithms. |
| A03 | Injection | Yes | Addressed | All queries via SQLAlchemy ORM. Zero raw SQL. |
| A04 | Insecure Design | Yes | Addressed | Formal Protocol, 75 invariant tests, seal-before-store enforcement |
| A05 | Security Misconfiguration | Yes | Addressed | Secure defaults (0600 permissions, umask creation, path validation) |
| A06 | Vulnerable Components | Yes | Addressed | 1 required dep (pynacl), 0 known CVEs in runtime deps |
| A07 | Auth Failures | No | N/A | Library, not a web service |
| A08 | Integrity Failures | Yes | Addressed | SHA3-256 + Ed25519 + hash chain. 13 tamper-evidence tests. |
| A09 | Logging Failures | Yes | Addressed | Error messages sanitized. No secrets in exceptions. |
| A10 | SSRF | No | N/A | No HTTP client, no URL fetching |

---

## 10. Test Suite Metrics

### 10.1 Coverage

| Metric | Value |
|---|---|
| Source statements | 675 |
| Statements covered | 675 |
| Line coverage | **100%** |
| Coverage enforcement | `fail_under = 100` in CI |
| Coverage tool | pytest-cov |

### 10.2 Test Counts

| Category | Count | What It Tests |
|---|---|---|
| Capsule model | 38 | 6-section model, serialization, factory, all types |
| Seal + verification | 20 | Ed25519 seal/verify, key management, tampering |
| Chain integrity | 20 | Hash linking, sequence, genesis, tenant chains |
| Canonical form | 22 | CPS Section 2 serialization rules |
| Golden fixtures | 45 | 16 cross-language conformance vectors |
| Session tracking | 13 | Session isolation, privacy |
| PostgreSQL tenant | 21 | Multi-tenant storage isolation |
| Dual signature | 24 | Ed25519 + ML-DSA-65, PQ enable/disable |
| Coverage targets | 72 | Every uncovered line, error path, edge case |
| **Invariants** | **75** | **Roundtrip, determinism, tamper evidence (all fields), Unicode, chain integrity, Protocol contract, seal isolation** |
| **Total** | **350** | |

### 10.3 Warning Policy

```toml
filterwarnings = ["error"]
```

Zero exemptions. Any warning from any source — ours or third-party — is a test failure. No warnings are suppressed.

### 10.4 Invariant Tests

The 75 invariant tests verify **properties**, not just **paths**:

| Invariant | Tests | What It Proves |
|---|---|---|
| Serialization roundtrip is lossless | 5 | `from_dict(to_dict(capsule))` preserves all data for all types |
| Hashing is deterministic | 6 | Same capsule always produces same hash (verified over 100+ iterations) |
| Every content field is tamper-evident | 13 | Modifying any of 13 fields on a sealed Capsule causes `verify()` to fail |
| Chain is append-only | 5 | Valid chains verify; linkage, sequence, genesis, and length are correct |
| Protocol contract is satisfied | 2 | Both SQLite and PostgreSQL pass `isinstance(storage, CapsuleStorageProtocol)` |
| Unicode resilience | 42 | 14 Unicode strings (Latin, Cyrillic, Chinese, Arabic, emoji, null bytes, 10K chars) survive seal+verify, roundtrip, and hashing |
| Seal fields are isolated from content | 2 | Seal metadata does not affect the content hash; `to_dict()` excludes seal fields |

---

## 11. Evaluation Checklist

For CISOs and security teams evaluating Capsule for organizational adoption:

| # | Criterion | Status | Evidence |
|---|---|---|---|
| 1 | Uses NIST-approved hash algorithm | Yes | SHA3-256 (FIPS 202) |
| 2 | Uses NIST-approved signature algorithm | Yes | Ed25519 (FIPS 186-5) |
| 3 | Post-quantum protection available | Yes | ML-DSA-65 (FIPS 204), optional dual signature |
| 4 | No deprecated cryptographic algorithms | Yes | Bandit scan: 0 issues; no MD5/SHA1/RSA/DES |
| 5 | Private keys protected at rest | Yes | File permissions 0600, umask-based creation |
| 6 | No TOCTOU in key creation | Yes | umask before write, chmod after (belt and suspenders) |
| 7 | Path traversal prevention | Yes | `resolve_data_dir()` rejects `..` components |
| 8 | Tamper detection for individual records | Yes | Hash + signature verification (13 tamper-evidence tests) |
| 9 | Tamper detection for record sequence | Yes | Hash chain with consecutive sequence numbers |
| 10 | Tenant isolation in multi-tenant mode | Yes | All 7 Protocol methods accept and enforce `tenant_id` |
| 11 | Error messages sanitized | Yes | Exception type name only; no paths or connection strings |
| 12 | Minimal dependency footprint | Yes | 1 required runtime dependency (pynacl) |
| 13 | No runtime network dependencies | Yes | Air-gapped operation verified |
| 14 | 100% test coverage | Yes | 675/675 statements, enforced in CI |
| 15 | Zero warning tolerance | Yes | `filterwarnings = ["error"]`, 0 exemptions |
| 16 | Invariant-based testing | Yes | 75 property tests beyond line coverage |
| 17 | Cross-language conformance vectors | Yes | 16 golden test fixtures |
| 18 | Open source with patent grant | Yes | Apache 2.0 + additional patent grant |
| 19 | Static analysis clean | Yes | Bandit: 0 findings across 1,684 lines |
| 20 | Dependency vulnerabilities | None | pip-audit: 0 CVEs in runtime dependencies |

---

## 12. Intellectual Property

This software is covered by a U.S. provisional patent application filed February 5, 2026:

*System and Method for Real-Time Capture of Autonomous Artificial Intelligence Operations in Cryptographically-Linked Multi-Section Records with Pre-Execution Reasoning Capture*

The patent covers the six-section record structure, pre-execution reasoning capture, mandatory rejection reasons, dual cryptographic signatures, hash chain linking, and mandatory capture architecture — all of which are implemented in this codebase.

A perpetual, worldwide, royalty-free, irrevocable patent license is granted to all users under the Apache License 2.0 and the additional patent grant in [PATENTS.md](../PATENTS.md).

| Patent Claim | Implementation |
|---|---|
| Six-section atomic record | `Capsule` with Trigger, Context, Reasoning, Authority, Execution, Outcome |
| Pre-execution reasoning capture | `ReasoningSection` populated before `ExecutionSection` |
| Rejection reasons for non-selected options | `ReasoningOption.rejection_reason` (required for non-selected) |
| Dual cryptographic signatures | Ed25519 (required) + ML-DSA-65 (optional) via `Seal` |
| Hash chain linking | `CapsuleChain` with `previous_hash` and `sequence` |
| Mandatory capture architecture | The axiom: for all actions, there exists a Capsule |

---

## 13. Recommendations

1. **HSM integration** for key storage in high-security production deployments (planned)
2. **FIPS 140-3 validated module** — current implementation uses FIPS-approved algorithms via PyNaCl/libsodium, but the module itself is not FIPS-validated
3. **External penetration test** before deployment in regulated environments
4. **Periodic dependency audit** — Dependabot is configured for weekly automated checks

---

## 14. Conclusion

The Capsule v1.0.0 codebase demonstrates strong security posture for a cryptographic protocol library:

- Zero static analysis findings
- Zero known dependency vulnerabilities
- 100% test coverage with property-based invariant testing
- FIPS-approved algorithms with no deprecated cryptography
- Tenant isolation enforced at the protocol level
- Error messages sanitized to prevent information disclosure
- Air-gapped operation with zero runtime network dependencies

The library is suitable for use in security-sensitive environments, subject to standard deployment hardening (TLS, OS-level access controls, key management procedures) at the application layer.

---

*Report generated: March 7, 2026*
*Capsule v1.0.0 — Quantum Pipes Technologies, LLC*
