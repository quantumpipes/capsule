# Implementor's Guide

> **How to build a conformant Capsule Protocol implementation in any language.**

This guide walks through the requirements for implementing the Capsule Protocol Specification (CPS) in a new language. The Python reference implementation at [`reference/python/`](../reference/python/) serves as the canonical example.

---

## What You Need to Implement

A conformant CPS implementation provides 9 capabilities:

| # | Capability | Function |
|---|---|---|
| 1 | **Data model** | Capsule with all 6 sections and all fields |
| 2 | **to_dict()** | Convert Capsule to a plain dictionary/map |
| 3 | **from_dict()** | Deserialize Capsule from dictionary/map |
| 4 | **canonicalize()** | Serialize dict to canonical JSON (CPS Section 2) |
| 5 | **compute_hash()** | SHA3-256 of canonical JSON |
| 6 | **seal()** | Compute hash + Ed25519 signature |
| 7 | **verify()** | Recompute hash and verify signature |
| 8 | **Chain verification** | Validate sequence numbers and hash linkage |
| 9 | **Conformance** | Pass all 16 golden test vectors |

---

## Step 1: Data Model

Implement the Capsule structure with all 12 top-level fields and 6 sections. See [CPS Section 1](../spec/README.md#1-capsule-structure) for the complete field-level specification.

Key decisions per language:

| Concern | Guidance |
|---|---|
| **Null vs. empty** | Distinguish between `null` and `""`. The `empty_vs_null` fixture tests this. |
| **Float vs. integer** | `reasoning.confidence` and `reasoning.options[].feasibility` must serialize as floats (`0.0`, not `0`). |
| **DateTime** | Use ISO 8601 with `+00:00` suffix, never `Z`. |
| **UUID** | Lowercase hexadecimal with hyphens. |

---

## Step 2: Canonical JSON

This is the hardest part. The canonical JSON rules in [CPS Section 2](../spec/README.md#2-canonical-json-serialization-rules) must be followed exactly:

1. **Key ordering**: Lexicographic by Unicode code point, recursive
2. **Whitespace**: Zero. No spaces after `:` or `,`
3. **Float fields**: `confidence` and `feasibility` always serialize with decimal point
4. **DateTime**: `YYYY-MM-DDTHH:MM:SS+00:00` format
5. **String escaping**: Literal UTF-8 for non-ASCII, do NOT escape `/`

### Language-Specific Pitfalls

| Language | Pitfall | Fix |
|---|---|---|
| **JavaScript/TypeScript** | `JSON.stringify` doesn't distinguish float from integer | Track float-typed field paths and append `.0` for integer values (see `reference/typescript/src/canonical.ts`) |
| **Go** | `json.Marshal` escapes `<`, `>`, `&` by default | Use `json.NewEncoder` with `SetEscapeHTML(false)` |
| **Rust** | `serde_json` produces correct output by default | Ensure `ensure_ascii` is not enabled |
| **Python** | `json.dumps` escapes non-ASCII by default | Use `ensure_ascii=False` |

### Validation

Run your canonicalization against every `capsule_dict` → `canonical_json` pair in [`conformance/fixtures.json`](../conformance/fixtures.json). Byte-identical output is required.

---

## Step 3: SHA3-256 Hashing

```
canonical_json_string → UTF-8 bytes → SHA3-256 → 64-character lowercase hex string
```

Every major language has a SHA3-256 library:

| Language | Library | Notes |
|---|---|---|
| Python | `hashlib.sha3_256` | stdlib, no dependency needed |
| TypeScript | `@noble/hashes` ^2.0.1 | Audited, zero-dep, ESM-only; import from `@noble/hashes/sha3.js` |
| Go | `golang.org/x/crypto/sha3` | Official Go extended crypto |
| Rust | `sha3` crate | RustCrypto project |

Validate against every `canonical_json` → `sha3_256_hash` pair in the conformance suite.

---

## Step 4: Ed25519 Signing

```
sha3_hex_string (64 ASCII chars) → UTF-8 bytes → Ed25519 sign → 128-character hex string
```

**Critical**: Sign the hex-encoded hash *string* (64 ASCII characters as UTF-8 bytes), not the raw 32-byte hash value. This is intentional and must be replicated exactly.

| Language | Library | Notes |
|---|---|---|
| Python | `pynacl` >=1.6.2 | libsodium bindings, includes CVE-2025-69277 fix |
| TypeScript | `@noble/ed25519` ^3.0.0 | Audited, 5KB, RFC 8032 + FIPS 186-5 compliant |
| Go | `crypto/ed25519` | stdlib, no dependency needed |
| Rust | `ed25519-dalek` crate | RustCrypto project |

---

## Step 5: Verification

```
1. Extract hash and signature from sealed Capsule
2. Recompute canonical JSON from content (seal fields excluded)
3. Compute SHA3-256 of canonical JSON
4. Compare computed hash to stored hash (exact match)
5. Verify Ed25519 signature over the stored hash string
```

Seal fields (`hash`, `signature`, `signature_pq`, `signed_at`, `signed_by`) are NOT part of the canonical content.

---

## Step 6: Chain Verification

Implementations SHOULD support two verification levels (see [CPS Section 7.5](../spec/README.md)):

**Structural** (fast):

```
1. Load all Capsules in sequence order
2. Verify sequence numbers are consecutive: 0, 1, 2, ...
3. Verify genesis (sequence 0) has previous_hash = null
4. For each subsequent Capsule, verify previous_hash = hash of previous Capsule
```

**Cryptographic** (thorough):

```
All structural checks, plus:
5. For each Capsule, recompute SHA3-256 from content via to_dict() + canonicalize()
6. Compare recomputed hash to stored hash (detects storage-level tampering)
7. Optionally verify Ed25519 signature on each Capsule
```

Structural verification trusts stored hash values. Cryptographic verification catches content tampering where the attacker does not have the signing key.

---

## Step 7: Conformance Testing

Run your implementation against all 16 fixtures in [`conformance/fixtures.json`](../conformance/fixtures.json):

```
for each fixture:
    input  = fixture.capsule_dict
    expect_json = fixture.canonical_json
    expect_hash = fixture.sha3_256_hash

    actual_json = canonicalize(to_dict(from_dict(input)))
    actual_hash = sha3_256(actual_json)

    assert actual_json == expect_json   # byte-identical
    assert actual_hash == expect_hash   # hash matches
```

If all 16 pass, your implementation is conformant.

---

## Step 8: URI Parsing (Optional)

Implementations may include a parser for `capsule://` URIs (see [`spec/uri-scheme.md`](../spec/uri-scheme.md)). A conformant URI parser must handle four forms:

| Form | Example | Key Fields |
|---|---|---|
| **Hash reference** | `capsule://sha3_<64hex>` | `reference_type: "hash"`, `hash_algorithm: "sha3"`, `hash_value` |
| **Chain + sequence** | `capsule://deploy-bot/42` | `chain`, `reference_type: "sequence"`, `sequence` |
| **Chain + hash** | `capsule://deploy-bot/sha3_<64hex>` | `chain`, `reference_type: "hash"`, `hash_value` |
| **ID reference** | `capsule://<uuid>` | `reference_type: "id"`, `id` |

All forms support optional fragments (`#reasoning`, `#execution/tool_calls/0`) using JSON Pointer syntax.

### Validation rules

- `sha3_` prefix must be followed by exactly 64 lowercase hex characters (`[0-9a-f]{64}`)
- Reject unknown hash algorithm prefixes
- Fragment paths must conform to the 6-section structure; reject path traversal attempts
- Sequence numbers must be non-negative integers

### Testing

Validate against [`conformance/uri-fixtures.json`](../conformance/uri-fixtures.json), which provides valid URIs with expected parse results and invalid URIs that must be rejected.

---

## Step 9: Key Management (Recommended)

Implementations SHOULD support epoch-based key rotation per [CPS Section 8](../spec/README.md#8-key-management-recommendations).

### Keyring

Maintain a keyring that maps fingerprints to public keys across rotation epochs. The Python reference uses `~/.quantumpipes/keyring.json`:

```json
{
  "version": 1,
  "active_epoch": 1,
  "epochs": [
    { "epoch": 0, "algorithm": "ed25519", "public_key_hex": "...", "fingerprint": "qp_key_a7f3", "status": "retired" },
    { "epoch": 1, "algorithm": "ed25519", "public_key_hex": "...", "fingerprint": "qp_key_8b1d", "status": "active" }
  ]
}
```

### Epoch-Aware Verification

When verifying a sealed Capsule:

```
1. Read capsule.signed_by fingerprint
2. Look up fingerprint in keyring → find epoch → get public_key_hex
3. Verify Ed25519 signature with the resolved key
4. If fingerprint not found, fall back to the local active key
```

This enables verification of Capsules signed across key rotations without manual key management.

### Rotation Protocol

```
1. Generate new Ed25519 key pair
2. Set current epoch status to "retired" with rotated_at timestamp
3. Add new epoch with status "active"
4. Securely overwrite old private key with new
5. Save keyring atomically (temp file + rename)
```

### Migration

On first use, if a key file exists but no keyring file, create the keyring with epoch 0 for the existing key. No user intervention required.

### Fingerprints

The Python reference uses `qp_key_XXXX` (first 4 hex characters of the public key). Implementations MAY use different formats but MUST ensure fingerprints are unique within a keyring. Legacy capsules may use a 16-character hex prefix as `signed_by`; the lookup function should match both formats.

---

## Registering Your Implementation

Once conformant, submit a PR to add your implementation to `reference/<language>/` and update the implementation matrix in [`reference/README.md`](../reference/README.md). See [CONTRIBUTING.md](../CONTRIBUTING.md) for details.

---

## Reference

- [CPS v1.0 Specification](../spec/) — The normative protocol spec
- [Conformance Suite](../conformance/) — Golden test vectors (16 valid + 15 invalid)
- [Python Reference](../reference/python/) — Python implementation (conformant, 668 tests, 100% coverage)
- [TypeScript Reference](../reference/typescript/) — TypeScript implementation (conformant, 101 tests, 100% coverage)
- [Go Verifier](https://github.com/quantumpipes/capsule-go) — Go verification library (conformant, verification only)
- [URI Scheme](../spec/uri-scheme.md) — Content-addressable references
