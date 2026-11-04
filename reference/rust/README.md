# Capsule: Rust reference

The Rust implementation of the [Capsule Protocol Specification](../../spec/). It creates, seals and verifies Capsules, and it passes all 16 golden vectors in [`conformance/fixtures.json`](../../conformance/fixtures.json).

```toml
[dependencies]
quantumpipes = { git = "https://github.com/quantumpipes/capsule", rev = "<commit>" }
```

```rust
use quantumpipes::{generate_signing_key, seal, verify, Capsule, CapsuleType};

let mut capsule = Capsule::new(CapsuleType::Agent);
capsule.trigger.request = "Deploy service v2.4".into();
let key = generate_signing_key();
seal(&mut capsule, &key).unwrap();
assert!(verify(&capsule, &key.verifying_key()).unwrap());
```

## What it implements

| Capability | Status |
|---|---|
| Capsule data model, `to_dict()` | Implemented |
| `canonicalize()` | Implemented; 16/16 fixtures byte-identical |
| `compute_hash()` (SHA3-256) | Implemented; 16/16 fixtures through the model |
| `seal()` / `verify()` (Ed25519) | Implemented |
| Chain verification (`verify_chain`) | Links only: sequence and `previous_hash`. It does not recompute hashes or check signatures; call `verify` on each capsule for that. |
| ML-DSA-65 (`signature_pq`) | Not yet; the field is written empty |
| Stored-document verification (CPS 3.5) | Not yet; `verify` hashes the model, so read the stored document before trusting a loaded record |
| `invalid-fixtures.json`, `stored-document-fixtures.json` | Not yet run |
| Floats in exponent range (below 1e-4, or 1e16 and above) | Not specified by CPS; Rust, Python and TypeScript each write them differently. Keep such values out of hashed fields until the spec defines them. |

## Test

```bash
cargo test --release --locked
cargo clippy --release --locked --all-targets -- -D warnings
```

`tests/conformance.rs` reads the fixtures from this repository, the same file Python and TypeScript test against. Set `CAPSULE_FIXTURES` to run a copy of the crate built elsewhere.
