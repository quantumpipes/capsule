# Contributing to the Capsule Protocol

Thank you for your interest in contributing to the Capsule Protocol. This repository contains both the protocol specification and reference implementations. Contributions are welcome to both.

## Repository Structure

```
capsule/
├── spec/               ← Protocol specification (CPS)
├── conformance/        ← Golden test vectors
├── reference/python/   ← Python reference implementation
├── reference/typescript/ ← TypeScript reference implementation
├── docs/               ← Protocol documentation
└── examples/           ← Language-agnostic example Capsules
```

## Types of Contributions

### Protocol Changes

Changes to the Capsule Protocol Specification itself — the record structure, canonical serialization rules, sealing algorithm, hash chain rules, or URI scheme. These affect all implementations.

Protocol changes are **rare and require careful review**. They must go through the [CPS change proposal](https://github.com/quantumpipes/capsule/issues/new?template=spec-change.md) process:

1. Written proposal with rationale
2. Golden test vector additions (in `conformance/`)
3. Backward compatibility analysis
4. Review by at least one maintainer

### Implementation Contributions

Changes to a reference implementation in `reference/<language>/`. These must not change the protocol — the canonical JSON output and sealing algorithm must remain identical. All golden fixtures must continue to pass.

- **Bug fixes** with regression tests
- **Storage backends** implementing `CapsuleStorageProtocol`
- **Performance improvements**
- **New language implementations** (see below)

### Documentation

Improvements to protocol documentation (`docs/`), implementation docs (`reference/<lang>/docs/`), or examples (`examples/`).

### New Language Implementations

We welcome reference implementations in new languages. To add one:

1. Open a [new implementation issue](https://github.com/quantumpipes/capsule/issues/new?template=new-implementation.md)
2. Create `reference/<language>/` with the implementation
3. The implementation must pass all 16 golden test vectors in `conformance/fixtures.json`
4. Include a README with installation, quickstart, and API overview

A conformant implementation must provide:

- [ ] Capsule data model with all 6 sections and all fields
- [ ] `to_dict()` — convert Capsule to a plain dictionary/map
- [ ] `canonicalize()` — serialize dict to canonical JSON (per CPS Section 2)
- [ ] `compute_hash()` — SHA3-256 of canonical JSON
- [ ] `seal()` — compute hash + Ed25519 signature
- [ ] `verify()` — recompute hash and verify signature
- [ ] `from_dict()` — deserialize Capsule from dictionary/map
- [ ] Pass all golden test vectors from `conformance/fixtures.json`
- [ ] Chain verification (sequence + hash linkage)

## Getting Started (Python)

```bash
cd reference/python
pip install -e ".[dev,storage]"
make test
```

This runs all tests with 100% coverage enforcement.

### Individual Commands (Python)

```bash
cd reference/python
make lint         # ruff check src/ tests/
make typecheck    # mypy src/qp_capsule/
make test-golden  # Golden fixture conformance tests only
make test-all     # lint + typecheck + test + golden
```

### Code Standards (Python)

- Python 3.11+ with type hints on all public functions
- Ruff for linting (E, F, I, W rules)
- mypy strict mode
- 100% test coverage required (`fail_under = 100`)
- `filterwarnings = ["error"]` — any new warning is a test failure

## Getting Started (TypeScript)

```bash
cd reference/typescript
npm ci
npm test
```

### Individual Commands (TypeScript)

```bash
cd reference/typescript
npm run lint          # tsc --noEmit
npm test              # vitest run (101 tests)
npm run conformance   # Golden fixture conformance tests only
```

### Code Standards (TypeScript)

- TypeScript 5.9+ with strict mode
- ESM-only (`.js` extensions in imports)
- Node.js >= 20.19.0

## Submitting Changes

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes (tests required for implementation changes)
4. Submit a pull request using the [PR template](./.github/PULL_REQUEST_TEMPLATE.md)

## Contributor License Agreement

By submitting contributions to this project, you agree that your contributions are licensed under the Apache License 2.0, including the patent grant in Section 3. See [PATENTS.md](./PATENTS.md) for details.

## Security

Report security vulnerabilities via [SECURITY.md](./SECURITY.md). Do not open public issues for security bugs.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](./CODE_OF_CONDUCT.md).
