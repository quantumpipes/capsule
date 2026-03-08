/**
 * Chain: Temporal integrity verification.
 *
 * Each Capsule links to the previous via hash, forming an unbroken chain.
 * Tampering with any record invalidates every record that follows.
 *
 * @license Apache-2.0
 */

import type { Capsule } from "./capsule.js";
import { toDict } from "./capsule.js";
import { computeHash } from "./seal.js";

export interface ChainVerificationResult {
  valid: boolean;
  error: string | null;
  broken_at: string | null;
  capsules_verified: number;
}

export interface ChainVerifyOptions {
  /** Recompute SHA3-256 from content and compare to stored hash. */
  verifyContent?: boolean;
}

/**
 * Verify the integrity of a Capsule chain.
 *
 * Structural checks (always):
 * 1. Sequence numbers are consecutive (0, 1, 2, ...)
 * 2. Each Capsule's previous_hash matches the prior Capsule's hash
 * 3. Genesis Capsule (sequence 0) has previous_hash = null
 *
 * Cryptographic check (when verifyContent is true):
 * 4. Recompute SHA3-256 from content and compare to stored hash
 *
 * @param capsules Array of Capsules sorted by sequence (ascending)
 * @param options Optional verification options
 */
export function verifyChain(
  capsules: Capsule[],
  options?: ChainVerifyOptions,
): ChainVerificationResult {
  const verifyContent = options?.verifyContent ?? false;

  if (capsules.length === 0) {
    return { valid: true, error: null, broken_at: null, capsules_verified: 0 };
  }

  for (let i = 0; i < capsules.length; i++) {
    const capsule = capsules[i];

    if (capsule.sequence !== i) {
      return {
        valid: false,
        error: `Sequence gap: expected ${i}, got ${capsule.sequence}`,
        broken_at: capsule.id,
        capsules_verified: i,
      };
    }

    if (i === 0) {
      if (capsule.previous_hash !== null) {
        return {
          valid: false,
          error: "Genesis Capsule has previous_hash (should be null)",
          broken_at: capsule.id,
          capsules_verified: 0,
        };
      }
    } else {
      const expectedPrev = capsules[i - 1].hash;
      if (capsule.previous_hash !== expectedPrev) {
        return {
          valid: false,
          error: `Chain broken: previous_hash mismatch at sequence ${i}`,
          broken_at: capsule.id,
          capsules_verified: i,
        };
      }
    }

    if (verifyContent) {
      const computed = computeHash(toDict(capsule));
      if (computed !== capsule.hash) {
        return {
          valid: false,
          error: `Content hash mismatch at sequence ${i}: stored hash does not match recomputed hash`,
          broken_at: capsule.id,
          capsules_verified: i,
        };
      }
    }
  }

  return {
    valid: true,
    error: null,
    broken_at: null,
    capsules_verified: capsules.length,
  };
}
