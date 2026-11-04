//! ML-DSA-65 (CPS 3.3): the cross-language vectors in
//! `conformance/pq-signature-fixtures.json`, and the hybrid seal round trip.

use quantumpipes::{
    generate_pq_keypair, generate_signing_key, pq_verify, pq_verifying_key_from_bytes, seal,
    seal_hybrid, verify, verify_hybrid, Capsule, CapsuleType, PQ_SIGNATURE_LEN,
};
use std::path::PathBuf;

fn vectors() -> serde_json::Value {
    // CAPSULE_PQ_FIXTURES overrides the path for a copy of this crate built outside the repo.
    let path = std::env::var_os("CAPSULE_PQ_FIXTURES").map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/pq-signature-fixtures.json")
    });
    assert!(path.is_file(), "PQ fixtures not found at {}; set CAPSULE_PQ_FIXTURES", path.display());
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn python_signed_vectors_verify_and_tampered_ones_fail() {
    let v = vectors();
    assert_eq!(v["algorithm"], "ML-DSA-65");
    let pk = pq_verifying_key_from_bytes(&hex::decode(v["public_key"].as_str().unwrap()).unwrap()).unwrap();
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.iter().any(|c| c["valid"] == true) && cases.iter().any(|c| c["valid"] == false));
    for c in cases {
        let got = pq_verify(&pk, c["hash"].as_str().unwrap(), c["signature_pq"].as_str().unwrap());
        assert_eq!(got, c["valid"].as_bool().unwrap(), "{}", c["name"]);
    }
}

fn sample() -> Capsule {
    let mut c = Capsule::new(CapsuleType::Agent);
    c.trigger.request = "Deploy service v2.4".into();
    c
}

#[test]
fn hybrid_seal_writes_both_signatures_and_verifies() {
    let (key, (pq_pk, pq_sk)) = (generate_signing_key(), generate_pq_keypair().unwrap());
    let mut c = sample();
    seal_hybrid(&mut c, &key, &pq_sk).unwrap();
    assert_eq!(c.signature_pq.len(), PQ_SIGNATURE_LEN * 2);
    assert!(verify(&c, &key.verifying_key()).unwrap());
    assert!(verify_hybrid(&c, &key.verifying_key(), &pq_pk).unwrap());
}

#[test]
fn hybrid_verification_is_fail_closed() {
    let key = generate_signing_key();
    let (pq_pk, pq_sk) = generate_pq_keypair().unwrap();
    let (other_pk, _) = generate_pq_keypair().unwrap();

    // Ed25519-only capsule: plain verify passes, hybrid refuses.
    let mut plain = sample();
    seal(&mut plain, &key).unwrap();
    assert!(plain.signature_pq.is_empty());
    assert!(!verify_hybrid(&plain, &key.verifying_key(), &pq_pk).unwrap());

    let mut c = sample();
    seal_hybrid(&mut c, &key, &pq_sk).unwrap();

    // Wrong PQ key.
    assert!(!verify_hybrid(&c, &key.verifying_key(), &other_pk).unwrap());

    // Stripped PQ signature.
    let mut stripped = c.clone();
    stripped.signature_pq.clear();
    assert!(!verify_hybrid(&stripped, &key.verifying_key(), &pq_pk).unwrap());

    // Edited content: the hash check fails before either signature is consulted.
    let mut edited = c.clone();
    edited.trigger.request = "Deploy service v9".into();
    assert!(!verify_hybrid(&edited, &key.verifying_key(), &pq_pk).unwrap());

    // A valid PQ signature cannot rescue a bad Ed25519 signature.
    let other_ed = generate_signing_key();
    assert!(!verify_hybrid(&c, &other_ed.verifying_key(), &pq_pk).unwrap());
}

#[test]
fn malformed_signatures_fail_without_an_error() {
    let key = generate_signing_key();
    let (pq_pk, pq_sk) = generate_pq_keypair().unwrap();
    let mut c = sample();
    seal_hybrid(&mut c, &key, &pq_sk).unwrap();
    for bad in ["zz", "abcd", ""] {
        let mut m = c.clone();
        m.signature = bad.into();
        assert_eq!(verify(&m, &key.verifying_key()), Ok(false), "Ed25519 {bad:?}");
        assert_eq!(verify_hybrid(&m, &key.verifying_key(), &pq_pk), Ok(false), "hybrid {bad:?}");
    }
}

#[test]
fn private_key_bytes_round_trip_and_sign() {
    let key = generate_signing_key();
    let (pq_pk, pq_sk) = generate_pq_keypair().unwrap();
    let bytes = quantumpipes::pq_signing_key_to_bytes(&pq_sk);
    assert_eq!(bytes.len(), 4032);
    let loaded = quantumpipes::pq_signing_key_from_bytes(&bytes).unwrap();
    let mut c = sample();
    seal_hybrid(&mut c, &key, &loaded).unwrap();
    assert!(verify_hybrid(&c, &key.verifying_key(), &pq_pk).unwrap());
    assert!(quantumpipes::pq_signing_key_from_bytes(&bytes[..4031]).is_err());
}
