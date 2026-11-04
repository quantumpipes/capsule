//! CPS conformance: the 16 golden vectors in `conformance/fixtures.json`.
//!
//! Each fixture must canonicalize byte-for-byte and hash identically, both from the
//! raw dict and through the `Capsule` model, so a Rust capsule verifies in Python and
//! TypeScript and the reverse.

use quantumpipes::{canonicalize, compute_hash, Capsule};
use sha3::{Digest, Sha3_256};
use std::path::PathBuf;

fn fixtures() -> serde_json::Value {
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidates = [
        here.join("../../conformance/fixtures.json"),             // this repo: reference/rust
        here.join("../../repos/capsule/conformance/fixtures.json"), // a monorepo that vendors this repo under repos/capsule
    ];
    let path = candidates.iter().find(|p| p.is_file()).expect("conformance/fixtures.json not found");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn all_sixteen_fixtures_canonicalize_and_hash() {
    let d = fixtures();
    let fx = d["fixtures"].as_array().unwrap();
    assert_eq!(fx.len(), 16);
    for f in fx {
        let name = f["name"].as_str().unwrap();
        let c = canonicalize(&f["capsule_dict"]).unwrap();
        assert_eq!(c, f["canonical_json"].as_str().unwrap(), "{name}: canonical JSON differs");
        assert_eq!(hex::encode(Sha3_256::digest(c.as_bytes())), f["sha3_256_hash"].as_str().unwrap(), "{name}: hash differs");
    }
}

#[test]
fn all_sixteen_fixtures_round_trip_through_the_model() {
    for f in fixtures()["fixtures"].as_array().unwrap() {
        let name = f["name"].as_str().unwrap();
        let cap: Capsule = serde_json::from_value(f["capsule_dict"].clone()).unwrap();
        assert_eq!(compute_hash(&cap).unwrap(), f["sha3_256_hash"].as_str().unwrap(), "{name}: model hash differs");
    }
}

#[test]
fn new_capsules_carry_the_spec_version() {
    assert_eq!(Capsule::new(quantumpipes::CapsuleType::Agent).to_dict()["spec_version"], "1.0");
}
