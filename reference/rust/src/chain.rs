//! Chain: Temporal integrity verification.
//!
//! Each Capsule links to the previous via hash, forming an unbroken chain.

use crate::capsule::Capsule;

/// Result of chain verification.
#[derive(Debug)]
pub struct ChainVerificationResult {
    pub valid: bool,
    pub error: Option<String>,
    pub broken_at: Option<String>,
    pub capsules_verified: usize,
}

/// Verify the integrity of a Capsule chain.
///
/// Capsules must be sorted by sequence (ascending). Checks:
/// - Sequence numbers are consecutive (0, 1, 2, ...)
/// - Each Capsule's previous_hash matches the prior Capsule's hash
/// - Genesis Capsule (sequence 0) has previous_hash = None
pub fn verify_chain(capsules: &[Capsule]) -> ChainVerificationResult {
    if capsules.is_empty() {
        return ChainVerificationResult {
            valid: true,
            error: None,
            broken_at: None,
            capsules_verified: 0,
        };
    }

    for (i, capsule) in capsules.iter().enumerate() {
        if capsule.sequence != i as i64 {
            return ChainVerificationResult {
                valid: false,
                error: Some(format!(
                    "Sequence gap: expected {}, got {}",
                    i, capsule.sequence
                )),
                broken_at: Some(capsule.id.clone()),
                capsules_verified: i,
            };
        }

        if i == 0 {
            if capsule.previous_hash.is_some() {
                return ChainVerificationResult {
                    valid: false,
                    error: Some(
                        "Genesis Capsule has previous_hash (should be null)".into(),
                    ),
                    broken_at: Some(capsule.id.clone()),
                    capsules_verified: 0,
                };
            }
        } else {
            let expected_prev = &capsules[i - 1].hash;
            match &capsule.previous_hash {
                Some(prev) if prev == expected_prev => {}
                _ => {
                    return ChainVerificationResult {
                        valid: false,
                        error: Some(format!(
                            "Chain broken: previous_hash mismatch at sequence {}",
                            i
                        )),
                        broken_at: Some(capsule.id.clone()),
                        capsules_verified: i,
                    };
                }
            }
        }
    }

    ChainVerificationResult {
        valid: true,
        error: None,
        broken_at: None,
        capsules_verified: capsules.len(),
    }
}
