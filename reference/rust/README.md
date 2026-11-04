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

Hybrid, post-quantum:

```rust
use quantumpipes::{generate_pq_keypair, seal_hybrid, verify_hybrid};

let (pq_public, pq_private) = generate_pq_keypair().unwrap();
seal_hybrid(&mut capsule, &key, &pq_private).unwrap();
assert!(verify_hybrid(&capsule, &key.verifying_key(), &pq_public).unwrap());
```

## What it implements

| Capability | Status |
|---|---|
| Capsule data model, `to_dict()` | Implemented |
| `canonicalize()` | Implemented; 16/16 fixtures byte-identical |
| `compute_hash()` (SHA3-256) | Implemented; 16/16 fixtures through the model |
| `seal()` / `verify()` (Ed25519) | Implemented |
| Chain verification (`verify_chain`) | Links only: sequence and `previous_hash`. It does not recompute hashes or check signatures; call `verify` on each capsule for that. |
| ML-DSA-65 (`signature_pq`, CPS 3.3) | Implemented: `seal_hybrid` signs the hash string with Ed25519 and ML-DSA-65 (empty context). `verify_hybrid` is fail-closed: it requires both. `verify` checks Ed25519 only and never reads `signature_pq`, so call `verify_hybrid` wherever a record must survive a future break of Ed25519. Passes the 7 cases in `conformance/pq-signature-fixtures.json`, which Python's liboqs signed. Keys load and save in the raw FIPS 204 encoding the Python reference writes to `key.ml` and `key.ml.pub`; `pq_signing_key_to_bytes` returns a buffer wiped on drop. ML-DSA comes from the `fips204` crate, which is not FIPS-validated. |
| Stored-document verification (CPS 3.5) | Not yet; `verify` hashes the model, so read the stored document before trusting a loaded record |
| `invalid-fixtures.json`, `stored-document-fixtures.json` | Not yet run |
| Floats in exponent range (below 1e-4, or 1e16 and above) | Not specified by CPS; Rust, Python and TypeScript each write them differently. Keep such values out of hashed fields until the spec defines them. |

## Test

```bash
cargo test --release --locked
cargo clippy --release --locked --all-targets -- -D warnings
```

`tests/conformance.rs` reads the fixtures from this repository, the same file Python and TypeScript test against. `tests/pq.rs` reads `conformance/pq-signature-fixtures.json`. Set `CAPSULE_FIXTURES` or `CAPSULE_PQ_FIXTURES` to run a copy of the crate built elsewhere.
