//! # quantumpipes
//!
//! Tamper-evident audit records for AI operations.
//!
//! ∀ action: ∃ capsule
//!
//! Create, seal, and verify Capsules: the atomic record of every AI action.
//! Each Capsule has six sections (Trigger, Context, Reasoning, Authority,
//! Execution, Outcome) and is cryptographically sealed with SHA3-256 + Ed25519,
//! optionally joined by ML-DSA-65 (FIPS 204) with [`seal_hybrid`].
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use quantumpipes::{Capsule, CapsuleType, seal, verify, generate_signing_key};
//!
//! let mut capsule = Capsule::new(CapsuleType::Agent);
//! capsule.trigger.request = "Deploy service v2.4".into();
//! capsule.reasoning.confidence = 0.95;
//!
//! let key = generate_signing_key();
//! seal(&mut capsule, &key).unwrap();
//!
//! assert!(capsule.is_sealed());
//! assert!(verify(&capsule, &key.verifying_key()).unwrap());
//! ```
//!
//! ## Cross-Language Compatibility
//!
//! Capsules sealed in Rust verify in Python, TypeScript, and Go. Rust verifies
//! CPS 1.0 capsules that carry `spec_version`. All implementations follow the Capsule Protocol Specification
//! for byte-identical JSON serialization.

pub mod capsule;
pub mod canonical;
pub mod seal;
pub mod chain;

pub use capsule::*;
pub use canonical::canonicalize;
pub use seal::{
    compute_hash, generate_pq_keypair, generate_signing_key, pq_sign, pq_signing_key_from_bytes,
    pq_signing_key_to_bytes, pq_verify, pq_verifying_key_from_bytes, pq_verifying_key_to_bytes, seal, seal_hybrid, verify, verify_hybrid, PqSigningKey,
    PqVerifyingKey, PQ_SIGNATURE_LEN,
};
pub use chain::{verify_chain, ChainVerificationResult};
