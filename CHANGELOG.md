# Changelog

All notable changes to Capsule are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [1.5.2] - 2026-03-18

### Added

- **`Capsule.to_sealed_dict()`** — Serialize a Capsule including the cryptographic seal envelope (`hash`, `signature`, `signature_pq`, `signed_at`, `signed_by`). Returns everything from `to_dict()` plus the five seal fields. Use this when building API responses or exporting complete sealed records. `to_dict()` continues to return only the canonical content (the part that gets hashed).
- **`Capsule.from_sealed_dict(data)`** — Inverse of `to_sealed_dict()`. Deserializes both canonical content and seal envelope from a single dict. Missing seal keys default to empty values, so it also accepts plain `to_dict()` output. Enables full roundtrip: `seal → to_sealed_dict → from_sealed_dict → verify`.
- **21 new tests** across 4 test files — unit tests for both methods (happy path, edge cases, JSON serialization, non-mutation, exact key delta, partial seal fields), real-Seal integration tests (hash stability, verify-after-roundtrip), FastAPI endpoint assertions (seal fields present in list and get responses), and invariant tests (to_sealed_dict superset of to_dict).

### Fixed

- **FastAPI endpoints omitting seal envelope** — `GET /capsules/` and `GET /capsules/{id}` were using `to_dict()`, which excludes seal fields by design. Responses now use `to_sealed_dict()` and include `hash`, `signature`, `signature_pq`, `signed_at`, and `signed_by` alongside the capsule content.

---

## [1.5.1] - 2026-03-17

Storage column width fix. Prevents PostgreSQL `StorageError` on every capsule write.

### Fixed

- **`signed_at` column overflow on PostgreSQL** — `String(30)` was too narrow for `datetime.isoformat()` output from timezone-aware datetimes (32 characters for UTC `+00:00` suffix). Widened to `String(40)` in both `CapsuleModel` (SQLite) and `CapsuleModelPG` (PostgreSQL). SQLite was unaffected (it doesn't enforce `VARCHAR` length), but every `seal_and_store()` against PostgreSQL raised `StorageError: value too long for type character varying(30)`.
- **`signed_by` column zero headroom** — `String(16)` exactly matched the legacy 16-character hex fingerprint with no margin. Widened to `String(32)` in both models. The keyring `qp_key_XXXX` format (11 chars) was safe, but any future fingerprint format change would have caused the same overflow.

### Migration

- **New installations**: columns are created with the correct width by `create_all()`.
- **Existing PostgreSQL databases**:
  ```sql
  ALTER TABLE quantumpipes_capsules
    ALTER COLUMN signed_at TYPE VARCHAR(40),
    ALTER COLUMN signed_by TYPE VARCHAR(32);
  ```
- **Existing SQLite databases**: no action required (SQLite does not enforce `VARCHAR` length).

---

## [1.5.0] - 2026-03-15

Hash chain concurrency protection. Prevents race conditions where concurrent writes could fork the chain.

### Added

- **Optimistic retry in `seal_and_store()`** -- if a concurrent writer claims the same sequence number, the UNIQUE constraint rejects the duplicate and the method retries with the updated chain head. Up to 3 retries before raising `ChainConflictError`. Seal fields (hash, signature, metadata) are properly reset between attempts.
- **`ChainConflictError` exception** -- raised when `seal_and_store()` exhausts all retries due to sustained concurrent writes for the same tenant chain. Subclass of `ChainError`; includes tenant ID in the message.
- **`UNIQUE` constraint on sequence (SQLite)** -- `CapsuleModel` now enforces `UNIQUE(sequence)`, preventing duplicate sequence numbers at the database level. Defense-in-depth: even if application logic fails, the database rejects duplicates.
- **`UNIQUE` constraint on tenant + sequence (PostgreSQL)** -- `CapsuleModelPG` now enforces `UNIQUE(tenant_id, sequence)`, scoped per tenant. Two tenants can independently have sequence 0, but the same tenant cannot have two capsules at the same sequence.
- **Global chain protection (PostgreSQL)** -- a DDL event creates `CREATE UNIQUE INDEX ... WHERE tenant_id IS NULL` exclusively on PostgreSQL, preventing duplicate sequences in the global chain (tenant_id=NULL). Fires via `execute_if(dialect="postgresql")`; does not affect SQLite.
- **`_is_integrity_error()` helper** -- detects `IntegrityError` and `UniqueViolationError` exceptions even when wrapped in `StorageError.__cause__` chains. Supports SQLAlchemy, asyncpg, and aiosqlite error types.
- **36 new concurrency tests** (`test_chain_concurrency.py`) -- exception hierarchy (3), integrity error detection (6), retry behavior with mocks (7), UNIQUE constraint enforcement (2), end-to-end integration (6), model constraint verification (3), retry invariants including capsule identity preservation and warning emission (4), exception hierarchy completeness (3), CLI `_get_version()` (2).

### Security

- **TOCTOU race condition fixed** -- the `add()` → `seal()` → `store()` sequence previously had a time-of-check-time-of-use vulnerability where two concurrent writers could both read the same chain head and both store capsules with the same sequence number, silently forking the hash chain. The UNIQUE constraint converts this silent corruption into a detectable conflict, and the retry loop resolves it automatically.
- **Defense in depth** -- the fix operates at two layers: database constraints (cannot be bypassed by application bugs) and application-level retry (handles the race transparently). Non-integrity errors (disk failures, network issues) propagate immediately without retry.

### Migration

- **New installations**: constraints are created automatically by `create_all()`.
- **Existing databases**: run `ALTER TABLE capsules ADD CONSTRAINT uq_capsule_sequence UNIQUE (sequence)` (SQLite) or `ALTER TABLE quantumpipes_capsules ADD CONSTRAINT uq_capsule_tenant_sequence UNIQUE (tenant_id, sequence)` (PostgreSQL). If the table already contains duplicate sequences from a prior race condition, resolve duplicates before adding the constraint.

---

## [1.4.0] - 2026-03-15

Ecosystem expansion: Go verifier, LiteLLM integration, and negative conformance vectors.

### Added

- **Go verifier library** ([`capsule-go`](https://github.com/quantumpipes/capsule-go)) -- canonical JSON serialization, SHA3-256 hashing, Ed25519 signature verification, and structural/full/signature chain verification in Go. Passes all 16 golden conformance vectors. Uses `crypto/ed25519` (stdlib) and `golang.org/x/crypto/sha3`. Verification-only (no capsule creation).
- **LiteLLM integration** ([`capsule-litellm`](https://github.com/quantumpipes/capsule-litellm)) -- `CapsuleLogger` callback that seals every LLM call into a Capsule. Sync and async support. Captures prompt hash (SHA3-256), token metrics, latency, model identity, and error tracking. Install: `pip install capsule-litellm`.
- **Invalid capsule fixtures** (`conformance/invalid-fixtures.json`) -- 15 negative test vectors across 5 error categories: missing required fields, wrong types, invalid values, chain violations, and content tampering. Verifiers SHOULD reject all of these.
- **Python tests for invalid fixtures** (`test_invalid_fixtures.py`) -- 33 tests validating the invalid fixture suite: structure, missing fields, wrong types, invalid values, chain violations, integrity violation via `compute_hash()`, and coverage guard.
- **Ecosystem documentation** -- README restructured with Reference Implementations and Ecosystem Libraries sections. Architecture doc adds ecosystem diagram and library descriptions. Docs index adds ecosystem section.

---

## [1.3.0] - 2026-03-09

CLI verifier and epoch-based key rotation system.

### Added

- **`capsule` CLI** -- command-line tool for verification, inspection, and key management. Installed as a console script via `pip install qp-capsule`. Zero new dependencies (stdlib `argparse` + existing `pynacl`).
  - `capsule verify <source>` -- verify chain integrity from JSON files (`chain.json`) or SQLite databases (`--db`). Three verification levels: `--structural` (default, sequence + previous_hash linkage), `--full` (+ SHA3-256 recomputation), `--signatures` (+ Ed25519 verification via keyring). Output modes: colored terminal (default), `--json` (machine-readable for policy engines and CI), `--quiet` (exit code only: 0=pass, 1=fail, 2=error).
  - `capsule inspect` -- show a capsule's full 6-section content with seal metadata. Lookup by `--seq` or `--id` from JSON files or SQLite databases.
  - `capsule keys info` -- display keyring metadata, epoch history, and capsule counts per epoch.
  - `capsule keys rotate` -- generate new Ed25519 key pair, retire current key, update keyring. No downtime.
  - `capsule keys export-public` -- export current public key for third-party verification.
  - `capsule hash <file>` -- compute SHA3-256 of any file.
- **Epoch-based key rotation** (`keyring.py`) -- automated key lifecycle management aligned with NIST SP 800-57. Keyring stored at `~/.quantumpipes/keyring.json` with atomic writes for crash safety. Supports backward-compatible verification across key rotations via fingerprint lookup. Seamless migration from existing single-key installations (auto-creates epoch 0 on first encounter).
- **Epoch-aware signature verification** -- `Seal(keyring=kr)` uses the capsule's `signed_by` fingerprint to look up the correct epoch's public key from the keyring. Capsules signed with old keys continue to verify after rotation.
- **`KeyringError` exception** -- dedicated exception for keyring operations (load, save, rotate, lookup).
- **100+ new tests** -- keyring creation, migration, rotation, lookup, registration, export, atomic writes, edge cases. CLI verification (structural/full/signatures), inspection, key management, hash utility, ANSI color support, cross-rotation verification, seal+keyring integration. 100% code coverage maintained.

### Security

- Key rotation follows NIST SP 800-57 lifecycle: Generation, Active, Retired, Destroyed. Private keys are securely replaced on rotation (old key overwritten with new). Public keys are retained in the keyring for backward-compatible verification.
- Keyring writes are atomic (temp file + `os.replace`) to prevent corruption on crash.
- New `qp_key_XXXX` fingerprint format with backward-compatible lookup of legacy 16-char hex fingerprints.
- `Seal.verify()` resolves the verification key from the keyring when available, falling back to the local key. No manual key management during verification.

---

## [1.2.0] - 2026-03-08

Protocol-first restructure, TypeScript implementation, finalized URI scheme, full CapsuleType conformance, Security Considerations in spec, cryptographic chain verification, and 11-framework compliance directory.

### Changed

- **Protocol-first repository restructure** — the repo now presents as an open protocol specification, not a Python package:
  - Protocol specification at `spec/` (was `specs/cps/`)
  - Conformance suite at `conformance/` (was `specs/cps/fixtures.json`)
  - Python reference implementation at `reference/python/` (was root-level `src/`, `tests/`, `pyproject.toml`)
  - Protocol documentation at `docs/` (language-agnostic)
  - Python-specific docs at `reference/python/docs/`
  - No `pyproject.toml` at repo root — the repo is a protocol, not a package
- **Compliance restructured into per-framework directory** — `docs/compliance.md` replaced by `docs/compliance/` with individual documents per framework and a README index.

### Added

- **Security Considerations in CPS spec** (`spec/README.md` Section 7) — documents what CPS provides (integrity, authenticity, non-repudiation, ordering, quantum resistance) and what it does not (confidentiality, truthfulness, availability, identity binding). Covers signer key compromise, chain truncation, verification levels, replay, and timestamp trust.
- **Cryptographic chain verification** — `chain.verify(verify_content=True)` recomputes SHA3-256 from content and compares to stored hash. `chain.verify(seal=seal_instance)` also verifies Ed25519 signatures. Both Python and TypeScript implementations. Default structural-only behavior is unchanged (backward compatible).
- **11-framework compliance directory** (`docs/compliance/`) — per-framework regulatory mappings: NIST SP 800-53, NIST AI RMF, EU AI Act, SOC 2, ISO 27001, HIPAA, GDPR, PCI DSS, FedRAMP, FINRA, CMMC. Each document maps protocol-level capabilities to specific controls and lists complementary controls outside the protocol's scope.
- **NIST RFI submission archive** (`nist-submission/`) — exact artifacts submitted to NIST (Docket NIST-2025-0035), SHA-256 checksums, and README with normative/informative classification.
- **`capsule://` URI scheme (Active)** — content-addressable references to Capsule records via their SHA3-256 hash. Spec at `spec/uri-scheme.md`, finalized from Draft to Active. Supports hash references (`capsule://sha3_<hash>`), chain references (`capsule://chain/42`), ID references, and fragment syntax into the 6 sections.
- **URI conformance vectors** (`conformance/uri-fixtures.json`) — 10 valid and 11 invalid URI parsing test vectors for cross-language URI parser verification.
- **TypeScript reference implementation** — full CPS-conformant implementation at `reference/typescript/`: Capsule model with factories, canonical JSON serializer (CPS Section 2 with float-path handling), SHA3-256 hashing, Ed25519 seal/verify, and chain verification with `verifyContent` option. Passes all 16 golden fixtures. 101 tests, 100% coverage (v8). Uses `@noble/hashes` ^2.0.1, `@noble/ed25519` ^3.0.0, vitest ^4.0.0, TypeScript ^5.9.0. Node.js >= 20.19.0.
- **TypeScript release workflow** (`.github/workflows/typescript-release.yaml`) — npm publish with provenance on version tags, gated by conformance tests.
- **`vault` golden fixture** — conformance suite now covers all 8 CapsuleTypes (16 total fixtures, up from 15). The `vault_secret` fixture tests secret rotation with policy-based authority.
- **Implementor's Guide** (`docs/implementors-guide.md`) — step-by-step instructions for building a conformant CPS implementation in any language, with URI parsing section and language-specific pitfalls.
- **Why Capsules** (`docs/why-capsules.md`) — the case for cryptographic AI memory.
- **Protocol structure tests** — guards the protocol-first layout, spec completeness (including Security Considerations), conformance suite integrity, URI vectors, compliance directory, TypeScript alignment, markdown links, CI configuration, and root-level files.
- **Dependabot for TypeScript** — npm dependency updates for `reference/typescript/`.

### Security

- `chain.verify()` now supports cryptographic verification (`verify_content=True`, `seal=`) in addition to structural-only checks. Structural verification alone trusts stored hash values; cryptographic verification recomputes from content.
- Hash computation in chain verification uses the canonical `compute_hash()` function (Python) and `computeHash(toDict())` (TypeScript) to prevent divergence from the sealing path.
- Spec Section 7 explicitly documents non-goals: no confidentiality, no content truthfulness, no availability guarantees, no identity binding.

### Updated

- **Python dependencies** — pytest >=9.0.0, pytest-asyncio >=1.0.0, ruff >=0.15.0, mypy >=1.19.0, sqlalchemy >=2.0.48, asyncpg >=0.31.0, liboqs-python >=0.14.1.
- **CI workflows** — renamed to `python-ci.yaml` / `python-release.yaml`, trigger on `reference/python/**`, `conformance/**`, and `spec/**` paths with `working-directory: reference/python`.

---

## [1.1.0] - 2026-03-07

High-level API for zero-boilerplate integration. One class, one decorator, one context variable.

### Added

- **`Capsules` class** — single entry point that owns storage, chain, and seal. Zero-config default (`Capsules()` uses SQLite), PostgreSQL via URL string, or custom storage backend via `storage=` kwarg.
- **`@capsules.audit()` decorator** — wraps any async or sync function with automatic Capsule creation, sealing, and storage. Supports `type`, `tenant_from`, `tenant_id`, `trigger_from`, `source`, `domain`, and `swallow_errors` parameters.
- **`capsules.current()` context variable** — access and enrich the active Capsule during execution (set model, confidence, session, resources, summary).
- **`mount_capsules()` FastAPI integration** — mount three read-only endpoints (`GET /`, `GET /{id}`, `GET /verify`) onto any FastAPI application. FastAPI is not a hard dependency.
- **33 new tests** (23 audit + 10 FastAPI) — init variants, success/failure paths, swallow/propagate errors, tenant extraction, trigger extraction, source, context variable enrichment, sync support, timing, type resolution, FastAPI routes.

### Design Principles

- **Zero new dependencies** — uses only stdlib (`contextvars`, `logging`, `inspect`, `functools`). FastAPI import is guarded.
- **Additive only** — no existing files modified. All 361 existing tests pass unchanged.
- **Never blocks user code** — capsule errors are swallowed by default (`swallow_errors=True`). Decorated function's return value, exceptions, and timing are preserved exactly.
- **Progressively enrichable** — start with just the decorator, add `current()` enrichment later.

---

## [1.0.0] - 2026-03-07

Initial public release of the Capsule Protocol Specification (CPS) v1.0 reference implementation.

### Added

- **Capsule model** with 6 mandatory sections: Trigger, Context, Reasoning, Authority, Execution, Outcome
- **8 Capsule types**: agent, tool, system, kill, workflow, chat, vault, auth
- **Cryptographic sealing**: SHA3-256 (FIPS 202) + Ed25519 (FIPS 186-5)
- **Post-quantum dual signatures**: optional ML-DSA-65 (FIPS 204) via `pip install qp-capsule[pq]`
- **Hash chain**: tamper-evident linking with sequence numbers and `previous_hash`
- **CapsuleStorageProtocol**: runtime-checkable `typing.Protocol` for custom storage backends
- **SQLite storage**: zero-config persistence via `pip install qp-capsule[storage]`
- **PostgreSQL storage**: multi-tenant isolation via `pip install qp-capsule[postgres]`
- **Pre-execution reasoning capture**: Section 3 (Reasoning) written before Section 5 (Execution)
- **ReasoningOption.rejection_reason**: mandatory explanation for non-selected options
- **Key management**: auto-generated keys with `0600` permissions, umask-based creation
- **Cross-language interoperability**: canonical JSON serialization rules and 15 golden test vectors covering Unicode, fractional timestamps, all CapsuleTypes, chain sequences, deep nesting, failure paths
- **Documentation**: getting-started, architecture, API reference, security evaluation, compliance mapping, CPS specification summary
- **350 automated tests** across 14 test files with **100% code coverage** enforced in CI
- **CPS v1.0 specification** shipped with the repo at `spec/`
- **Apache 2.0 license** with additional patent grant

### Security

- Ed25519 signatures required on every Capsule
- SHA3-256 chosen over SHA-256 for length-extension resistance
- Key files created with restrictive umask (no TOCTOU race)
- ML-DSA-65 uses FIPS 204 standardized name
- Zero runtime network dependencies (air-gapped operation)
- `filterwarnings = ["error"]` with zero exemptions — any warning is a test failure
- 100% test coverage enforced (`fail_under = 100`)

---

[1.5.2]: https://github.com/quantumpipes/capsule/releases/tag/v1.5.2
[1.5.1]: https://github.com/quantumpipes/capsule/releases/tag/v1.5.1
[1.5.0]: https://github.com/quantumpipes/capsule/releases/tag/v1.5.0
[1.4.0]: https://github.com/quantumpipes/capsule/releases/tag/v1.4.0
[1.3.0]: https://github.com/quantumpipes/capsule/releases/tag/v1.3.0
[1.2.0]: https://github.com/quantumpipes/capsule/releases/tag/v1.2.0
[1.1.0]: https://github.com/quantumpipes/capsule/releases/tag/v1.1.0
[1.0.0]: https://github.com/quantumpipes/capsule/releases/tag/v1.0.0
