# Changelog

All notable changes to Capsule are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

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

[1.2.0]: https://github.com/quantumpipes/capsule/releases/tag/v1.2.0
[1.1.0]: https://github.com/quantumpipes/capsule/releases/tag/v1.1.0
[1.0.0]: https://github.com/quantumpipes/capsule/releases/tag/v1.0.0
