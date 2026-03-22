/**
 * Seal: Cryptographic proof for Capsules.
 *
 * SHA3-256 (FIPS 202) for content integrity + Ed25519 (FIPS 186-5) for authenticity.
 *
 * @license Apache-2.0
 */

import { sha3_256 } from "@noble/hashes/sha3.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import * as ed25519 from "@noble/ed25519";
import { canonicalize } from "./canonical.js";
import type { Capsule, CapsuleDict } from "./capsule.js";
import { toDict } from "./capsule.js";

// ---------------------------------------------------------------------------
// Hash
// ---------------------------------------------------------------------------

/**
 * Compute the SHA3-256 hash of a Capsule's content.
 * Returns a 64-character lowercase hex string.
 */
export function computeHash(capsuleDict: CapsuleDict): string {
  const canonical = canonicalize(capsuleDict);
  const bytes = new TextEncoder().encode(canonical);
  return bytesToHex(sha3_256(bytes));
}

/**
 * Compute the SHA3-256 hash of an arbitrary object.
 * Uses canonical JSON serialization (sorted keys, no whitespace).
 */
export function computeHashFromDict(data: Record<string, unknown>): string {
  const canonical = canonicalize(data);
  const bytes = new TextEncoder().encode(canonical);
  return bytesToHex(sha3_256(bytes));
}

// ---------------------------------------------------------------------------
// Sign
// ---------------------------------------------------------------------------

/**
 * Seal a Capsule — compute hash and Ed25519 signature.
 *
 * Critical: Signs the hex-encoded hash STRING (64 ASCII chars as UTF-8 bytes),
 * not the raw 32-byte hash value. This matches the Python reference implementation.
 */
export async function seal(
  capsule: Capsule,
  privateKey: Uint8Array,
): Promise<Capsule> {
  const dict = toDict(capsule);
  const hashHex = computeHash(dict);

  const hashBytes = new TextEncoder().encode(hashHex);
  const signature = await ed25519.signAsync(hashBytes, privateKey);

  const publicKey = await ed25519.getPublicKeyAsync(privateKey);

  capsule.hash = hashHex;
  capsule.signature = bytesToHex(signature);
  capsule.signature_pq = "";
  capsule.signed_at = new Date().toISOString().replace("Z", "+00:00");
  capsule.signed_by = bytesToHex(publicKey).slice(0, 16);

  return capsule;
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

/** FR-003: structured verify outcome (aligns with Python `SealVerifyCode`). */
export type SealVerifyCode =
  | "ok"
  | "missing_hash"
  | "missing_signature"
  | "malformed_hex"
  | "hash_mismatch"
  | "invalid_signature"
  | "pq_verification_failed"
  | "pq_library_unavailable"
  | "unsupported_algorithm";

export interface SealVerificationResult {
  ok: boolean;
  code: SealVerifyCode;
  message: string;
}

/**
 * Verify a sealed Capsule and return a structured result (FR-003).
 *
 * 1. Recompute SHA3-256 from content and compare to stored hash
 * 2. Verify Ed25519 signature over the hash string
 *
 * TS reference is classical-only; PQ codes are reserved for parity with Python.
 */
export async function verifyDetailed(
  capsule: Capsule,
  publicKey: Uint8Array,
): Promise<SealVerificationResult> {
  if (!capsule.hash) {
    return {
      ok: false,
      code: "missing_hash",
      message: "capsule has no hash field",
    };
  }
  if (!capsule.signature) {
    return {
      ok: false,
      code: "missing_signature",
      message: "capsule has no signature field",
    };
  }

  const _hashBytes = tryParseHex(capsule.hash, 32);
  if (_hashBytes === null) {
    return {
      ok: false,
      code: "malformed_hex",
      message: "hash must be 64 hex chars (32 bytes)",
    };
  }
  const sigBytes = tryParseHex(capsule.signature, 64);
  if (sigBytes === null) {
    return {
      ok: false,
      code: "malformed_hex",
      message: "signature must be 128 hex chars (64 bytes)",
    };
  }

  let computedHash: string;
  try {
    const dict = toDict(capsule);
    computedHash = computeHash(dict);
  } catch (e) {
    return {
      ok: false,
      code: "hash_mismatch",
      message: `could not compute content hash: ${String(e)}`,
    };
  }

  if (computedHash.toLowerCase() !== capsule.hash.toLowerCase()) {
    return {
      ok: false,
      code: "hash_mismatch",
      message: "recomputed hash does not match stored hash",
    };
  }

  const hashBytes = new TextEncoder().encode(capsule.hash);

  try {
    const valid = await ed25519.verifyAsync(sigBytes, hashBytes, publicKey);
    if (!valid) {
      return {
        ok: false,
        code: "invalid_signature",
        message: "Ed25519 signature verification failed",
      };
    }
  } catch (e) {
    return {
      ok: false,
      code: "invalid_signature",
      message: `Ed25519 verification error: ${String(e)}`,
    };
  }

  return { ok: true, code: "ok", message: "" };
}

/**
 * Verify a sealed Capsule's integrity and authenticity.
 *
 * Same as {@link verifyDetailed} but returns only success/failure.
 */
export async function verify(
  capsule: Capsule,
  publicKey: Uint8Array,
): Promise<boolean> {
  return (await verifyDetailed(capsule, publicKey)).ok;
}

// ---------------------------------------------------------------------------
// Key utilities
// ---------------------------------------------------------------------------

/** Generate a new Ed25519 key pair. */
export function generateKeyPair(): {
  privateKey: Uint8Array;
  publicKey: Promise<Uint8Array>;
} {
  const privateKey = ed25519.utils.randomSecretKey();
  return {
    privateKey,
    publicKey: ed25519.getPublicKeyAsync(privateKey),
  };
}

/** Get the public key fingerprint (first 16 hex chars). */
export async function getFingerprint(privateKey: Uint8Array): Promise<string> {
  const pub = await ed25519.getPublicKeyAsync(privateKey);
  return bytesToHex(pub).slice(0, 16);
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

/** Parse hex to exactly `byteLength` bytes; return null if invalid. */
function tryParseHex(hex: string, byteLength: number): Uint8Array | null {
  if (hex.length !== byteLength * 2 || !/^[0-9a-fA-F]+$/.test(hex)) {
    return null;
  }
  const out = new Uint8Array(byteLength);
  for (let i = 0; i < hex.length; i += 2) {
    const v = parseInt(hex.slice(i, i + 2), 16);
    if (Number.isNaN(v)) return null;
    out[i / 2] = v;
  }
  return out;
}
