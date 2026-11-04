# Reference Implementations

Reference implementations of the [Capsule Protocol Specification (CPS)](../spec/).

---

## Implementation Status

| Capability | [Python](./python/) | [TypeScript](./typescript/) | [Rust](./rust/) |
|---|:---:|:---:|:---:|
| Capsule data model | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `to_dict()` / `toDict()` | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `from_dict()` / `fromDict()` | :white_check_mark: | :white_check_mark: | :white_check_mark: (serde) |
| `canonicalize()` | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `compute_hash()` | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `seal()` | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `verify()` | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Chain verification | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Storage (SQLite) | :white_check_mark: | — | — |
| Storage (PostgreSQL) | :white_check_mark: | — | — |
| ML-DSA-65 (post-quantum) | :white_check_mark: Optional | — | Planned |
| **Conformance (16/16)** | **:white_check_mark: 16/16** | **:white_check_mark: 16/16** | **:white_check_mark: 16/16** |

:white_check_mark: = Implemented and passing conformance
— = Not applicable (storage and PQ are implementation-specific features)

### Other Languages

Go ships as a separate repo, [quantumpipes/capsule-go](https://github.com/quantumpipes/capsule-go) (planned). Rust lives here in [`rust/`](./rust/), so it is checked against these exact fixtures in the same CI as Python and TypeScript.

New language implementations import `conformance/fixtures.json` from this repo and pass all 16 golden vectors independently.

---

## Conformance Requirement

Every reference implementation must pass all 16 golden test vectors in [`conformance/fixtures.json`](../conformance/fixtures.json). An implementation is conformant when it produces byte-identical canonical JSON and matching SHA3-256 hashes for every fixture.

See the [Implementor's Guide](../docs/implementors-guide.md) for step-by-step instructions.

---

## Adding a New Language

1. Create `reference/<language>/` with your implementation
2. Pass all 16 conformance fixtures
3. Include a README with install, quickstart, and conformance status
4. Submit a PR — see [CONTRIBUTING.md](../CONTRIBUTING.md)
