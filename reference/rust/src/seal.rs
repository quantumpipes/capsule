//! Seal: Cryptographic proof for Capsules.
//!
//! SHA3-256 for content integrity, Ed25519 for authenticity (CPS 3.2), and an
//! optional ML-DSA-65 (FIPS 204) signature in `signature_pq` (CPS 3.3). Both
//! signatures cover the same 64-character hex hash string, with an empty
//! ML-DSA context. Under [`verify_hybrid`], forging a seal means breaking both
//! algorithms. [`verify`] checks Ed25519 only, so a verifier that needs
//! post-quantum proof must call `verify_hybrid`.

use ed25519_dalek::{Signer as _, SigningKey, Verifier as _, VerifyingKey};
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer as _, Verifier as _};
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

use crate::canonical::canonicalize;
use crate::capsule::Capsule;

/// An ML-DSA-65 private key (FIPS 204 encoding, 4032 bytes).
pub type PqSigningKey = ml_dsa_65::PrivateKey;
/// An ML-DSA-65 public key (FIPS 204 encoding, 1952 bytes).
pub type PqVerifyingKey = ml_dsa_65::PublicKey;

/// Length in bytes of an ML-DSA-65 signature.
pub const PQ_SIGNATURE_LEN: usize = ml_dsa_65::SIG_LEN;

/// Compute the SHA3-256 hash of a Capsule's content dict.
/// Returns a 64-character lowercase hex string.
pub fn compute_hash(capsule: &Capsule) -> Result<String, String> {
    let dict = capsule.to_dict();
    let canonical = canonicalize(&dict)?;
    let mut hasher = Sha3_256::new();
    hasher.update(canonical.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

/// Seal a Capsule with Ed25519 only. `signature_pq` is written empty.
pub fn seal(capsule: &mut Capsule, signing_key: &SigningKey) -> Result<(), String> {
    seal_with(capsule, signing_key, None)
}

/// Seal a Capsule with Ed25519 and ML-DSA-65 over the same hash string.
pub fn seal_hybrid(
    capsule: &mut Capsule,
    signing_key: &SigningKey,
    pq_key: &PqSigningKey,
) -> Result<(), String> {
    seal_with(capsule, signing_key, Some(pq_key))
}

fn seal_with(
    capsule: &mut Capsule,
    signing_key: &SigningKey,
    pq_key: Option<&PqSigningKey>,
) -> Result<(), String> {
    let hash_hex = compute_hash(capsule)?;

    // Sign the hex hash STRING (not raw bytes), matching the Python reference.
    let signature = signing_key.sign(hash_hex.as_bytes());
    let signature_pq = match pq_key {
        Some(k) => hex::encode(pq_sign(k, &hash_hex)?),
        None => String::new(),
    };

    let fingerprint = hex::encode(signing_key.verifying_key().as_bytes());

    capsule.hash = hash_hex;
    capsule.signature = hex::encode(signature.to_bytes());
    capsule.signature_pq = signature_pq;
    capsule.signed_at = Some(chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S+00:00").to_string());
    capsule.signed_by = fingerprint[..16].to_string();

    Ok(())
}

/// Verify a sealed Capsule's hash and Ed25519 signature ONLY.
///
/// `signature_pq` is not read, and it is not covered by the Ed25519 signature:
/// a capsule whose `signature_pq` was stripped or garbled still passes here.
/// Call [`verify_hybrid`] wherever a long-lived record needs post-quantum proof.
///
/// Malformed hex or a wrong signature length returns `Ok(false)`. `Err` means
/// the content could not be canonicalized.
#[must_use = "a verification result that is not checked verifies nothing"]
pub fn verify(capsule: &Capsule, verifying_key: &VerifyingKey) -> Result<bool, String> {
    if !capsule.is_sealed() {
        return Ok(false);
    }

    if compute_hash(capsule)? != capsule.hash {
        return Ok(false);
    }

    let Ok(sig_bytes) = hex::decode(&capsule.signature) else { return Ok(false) };
    let Ok(sig_arr) = <[u8; 64]>::try_from(sig_bytes.as_slice()) else { return Ok(false) };
    let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);

    Ok(verifying_key.verify(capsule.hash.as_bytes(), &signature).is_ok())
}

/// Verify the hash, the Ed25519 signature, AND the ML-DSA-65 signature.
///
/// Fail-closed: a capsule with an empty or malformed `signature_pq` returns
/// `Ok(false)`. This matches the Python reference's `require_pq=True`.
#[must_use = "a verification result that is not checked verifies nothing"]
pub fn verify_hybrid(
    capsule: &Capsule,
    verifying_key: &VerifyingKey,
    pq_key: &PqVerifyingKey,
) -> Result<bool, String> {
    if capsule.signature_pq.is_empty() || !verify(capsule, verifying_key)? {
        return Ok(false);
    }
    Ok(pq_verify(pq_key, &capsule.hash, &capsule.signature_pq))
}

/// Sign a hash string with ML-DSA-65 (CPS 3.3): the UTF-8 bytes of the hex
/// string, empty context, hedged randomness.
pub fn pq_sign(pq_key: &PqSigningKey, hash_hex: &str) -> Result<[u8; PQ_SIGNATURE_LEN], String> {
    pq_key.try_sign(hash_hex.as_bytes(), &[]).map_err(|e| format!("ML-DSA-65 signing failed: {e}"))
}

/// Verify an ML-DSA-65 signature (hex) over a hash string. Malformed hex or a
/// wrong length is a failed verification, never a panic.
#[must_use = "a verification result that is not checked verifies nothing"]
pub fn pq_verify(pq_key: &PqVerifyingKey, hash_hex: &str, signature_pq_hex: &str) -> bool {
    let Ok(bytes) = hex::decode(signature_pq_hex) else { return false };
    let Ok(sig) = <[u8; PQ_SIGNATURE_LEN]>::try_from(bytes.as_slice()) else { return false };
    pq_key.verify(hash_hex.as_bytes(), &sig, &[])
}

/// Generate a new Ed25519 signing key.
pub fn generate_signing_key() -> SigningKey {
    SigningKey::generate(&mut rand::thread_rng())
}

/// Generate a new ML-DSA-65 key pair from the OS random source.
pub fn generate_pq_keypair() -> Result<(PqVerifyingKey, PqSigningKey), String> {
    ml_dsa_65::KG::try_keygen().map_err(|e| format!("ML-DSA-65 key generation failed: {e}"))
}

/// Load an ML-DSA-65 public key from its 1952-byte FIPS 204 encoding, the
/// format the Python reference writes to `key.ml.pub`.
pub fn pq_verifying_key_from_bytes(bytes: &[u8]) -> Result<PqVerifyingKey, String> {
    let arr: [u8; ml_dsa_65::PK_LEN] =
        bytes.try_into().map_err(|_| format!("ML-DSA-65 public key must be {} bytes", ml_dsa_65::PK_LEN))?;
    PqVerifyingKey::try_from_bytes(arr).map_err(|e| format!("invalid ML-DSA-65 public key: {e}"))
}

/// Load an ML-DSA-65 private key from its 4032-byte FIPS 204 encoding, the
/// format the Python reference writes to `key.ml`.
pub fn pq_signing_key_from_bytes(bytes: &[u8]) -> Result<PqSigningKey, String> {
    if bytes.len() != ml_dsa_65::SK_LEN {
        return Err(format!("ML-DSA-65 private key must be {} bytes", ml_dsa_65::SK_LEN));
    }
    // The working copy is wiped on drop; the caller owns wiping `bytes`.
    let mut arr = Zeroizing::new([0u8; ml_dsa_65::SK_LEN]);
    arr.copy_from_slice(bytes);
    PqSigningKey::try_from_bytes(*arr).map_err(|e| format!("invalid ML-DSA-65 private key: {e}"))
}

/// Encode an ML-DSA-65 public key as its 1952-byte FIPS 204 encoding.
pub fn pq_verifying_key_to_bytes(key: &PqVerifyingKey) -> Vec<u8> {
    key.clone().into_bytes().to_vec()
}

/// Encode an ML-DSA-65 private key as its 4032-byte FIPS 204 encoding.
/// The returned buffer is wiped on drop; the caller owns protecting any copy
/// it writes to storage.
pub fn pq_signing_key_to_bytes(key: &PqSigningKey) -> Zeroizing<Vec<u8>> {
    let arr = Zeroizing::new(key.clone().into_bytes());
    Zeroizing::new(arr.to_vec())
}
