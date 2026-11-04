//! Seal: Cryptographic proof for Capsules.
//!
//! SHA3-256 for content integrity + Ed25519 for authenticity.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha3::{Digest, Sha3_256};

use crate::canonical::canonicalize;
use crate::capsule::Capsule;

/// Compute the SHA3-256 hash of a Capsule's content dict.
/// Returns a 64-character lowercase hex string.
pub fn compute_hash(capsule: &Capsule) -> Result<String, String> {
    let dict = capsule.to_dict();
    let canonical = canonicalize(&dict)?;
    let mut hasher = Sha3_256::new();
    hasher.update(canonical.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

/// Seal a Capsule: compute the hash and the Ed25519 signature.
pub fn seal(capsule: &mut Capsule, signing_key: &SigningKey) -> Result<(), String> {
    let hash_hex = compute_hash(capsule)?;

    // Sign the hex hash STRING (not raw bytes), matching the Python reference
    let signature = signing_key.sign(hash_hex.as_bytes());

    let verifying_key = signing_key.verifying_key();
    let fingerprint = hex::encode(verifying_key.as_bytes());

    capsule.hash = hash_hex;
    capsule.signature = hex::encode(signature.to_bytes());
    capsule.signature_pq = String::new();
    capsule.signed_at = Some(chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S+00:00").to_string());
    capsule.signed_by = fingerprint[..16].to_string();

    Ok(())
}

/// Verify a sealed Capsule's integrity and authenticity.
pub fn verify(capsule: &Capsule, verifying_key: &VerifyingKey) -> Result<bool, String> {
    if !capsule.is_sealed() {
        return Ok(false);
    }

    let computed_hash = compute_hash(capsule)?;

    if computed_hash != capsule.hash {
        return Ok(false);
    }

    let sig_bytes = hex::decode(&capsule.signature)
        .map_err(|e| format!("invalid signature hex: {}", e))?;

    let signature = ed25519_dalek::Signature::from_bytes(
        sig_bytes.as_slice().try_into().map_err(|_| "invalid signature length")?,
    );

    Ok(verifying_key.verify(capsule.hash.as_bytes(), &signature).is_ok())
}

/// Generate a new Ed25519 signing key.
pub fn generate_signing_key() -> SigningKey {
    SigningKey::generate(&mut rand::thread_rng())
}
