//! CPS conformance: the 16 golden vectors in `conformance/fixtures.json`.
//!
//! Each fixture must canonicalize byte-for-byte and hash identically, both from the
//! raw dict and through the `Capsule` model, so a Rust capsule verifies in Python and
//! TypeScript and the reverse.

use quantumpipes::{canonicalize, compute_hash, Capsule};
use sha3::{Digest, Sha3_256};
use std::path::PathBuf;

fn fixtures() -> serde_json::Value {
    // CAPSULE_FIXTURES overrides the path for a copy of this crate built outside the repo.
    let path = std::env::var_os("CAPSULE_FIXTURES")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/fixtures.json"));
    assert!(path.is_file(), "fixtures not found at {}; set CAPSULE_FIXTURES", path.display());
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
