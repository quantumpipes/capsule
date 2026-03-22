# Conformance Test Suite

**16 golden test vectors for cross-language interoperability.**

Any implementation of the Capsule Protocol Specification (CPS) must produce byte-identical output for these test vectors. If your implementation passes all 16 fixtures, it can seal and verify Capsules interchangeably with every other conformant implementation.

---

## How to Use

Each entry in `fixtures.json` contains three fields:

| Field | Type | Description |
|---|---|---|
| `capsule_dict` | object | The Capsule content as a JSON object (output of `to_dict()`) |
| `canonical_json` | string | The exact canonical JSON string your implementation must produce |
| `sha3_256_hash` | string | The expected SHA3-256 hex digest of the canonical JSON |

### Conformance check

For every fixture:

1. Feed `capsule_dict` into your canonicalization function
2. Compare the output byte-for-byte against `canonical_json`
3. Compute SHA3-256 of the canonical JSON bytes (UTF-8 encoded)
4. Compare the hash against `sha3_256_hash`

If all 16 pass, your implementation is conformant.

---

## Fixtures

| Fixture | Tests |
|---|---|
| **minimal** | Defaults, float `0.0`, nulls |
| **full** | All sections fully populated with options, tool calls, metrics |
| **kill_switch** | Kill switch activation (type `kill`, status `blocked`) |
| **tool_invocation** | Tool-type Capsule with tool call and error field |
| **chat_interaction** | Chat-type with session tracking |
| **workflow_hierarchy** | Workflow with `parent_id` hierarchy linking |
| **unicode_strings** | Non-ASCII in trigger, context, reasoning (UTF-8 conformance) |
| **fractional_timestamp** | Microsecond-precision datetime |
| **empty_vs_null** | Empty string vs null distinction (critical for Go, Rust, JS) |
| **confidence_one** | Confidence `1.0` serialized as `1.0`, not `1` |
| **deep_nesting** | Deeply nested objects testing recursive key sorting |
| **chain_genesis** | First Capsule in chain (sequence 0, previous_hash null) |
| **chain_linked** | Second Capsule with previous_hash set |
| **failure_with_error** | Failed tool call with error details |
| **auth_escalated** | Auth-type with MFA escalation chain |
| **vault_secret** | Vault-type with secret rotation and policy authority |

---

## Generating Fixtures

The fixture generator is written in Python but produces language-agnostic JSON:

```bash
cd conformance/
python generate_fixtures.py
```

This regenerates `fixtures.json` from the reference implementation. The generator uses the Python reference at `../reference/python/` as the source of truth.

---

## URI Conformance Vectors

The `uri-fixtures.json` file provides test vectors for `capsule://` URI parsing. Implementations that include a URI parser should validate against these vectors.

Each entry in the `valid` array contains:

| Field | Type | Description |
|---|---|---|
| `uri` | string | The `capsule://` URI to parse |
| `expected` | object | The expected parse result with `scheme`, `chain`, `reference_type`, `hash_algorithm`, `hash_value`, `sequence`, `id`, and `fragment` |

Each entry in the `invalid` array contains:

| Field | Type | Description |
|---|---|---|
| `uri` | string | A malformed or invalid URI |
| `reason` | string | Why this URI must be rejected |

### URI conformance check

For every valid fixture:

1. Parse the URI
2. Compare every field in the parse result against `expected`

For every invalid fixture:

1. Attempt to parse the URI
2. Confirm the parser rejects it (returns an error or null)

The URI spec is at [`spec/uri-scheme.md`](../spec/uri-scheme.md).

---

## Invalid Capsule Fixtures

The `invalid-fixtures.json` file provides 16 test vectors for **malformed or structurally invalid** capsules. A conformant verifier SHOULD reject each of these.

Each entry contains:

| Field | Type | Description |
|---|---|---|
| `capsule_dict` | object | A malformed capsule |
| `expected_error` | string | Error category: `missing_field`, `wrong_type`, `invalid_value`, `chain_violation`, `integrity_violation` |
| `error_field` | string | Which field caused the error |

### Error categories

| Category | Description | Example |
|---|---|---|
| `missing_field` | A required field is absent | No `id`, no `trigger` section, empty object |
| `wrong_type` | A field has the wrong JSON type | `sequence` is a string, `trigger` is an array |
| `invalid_value` | A field has an invalid value | Negative sequence, confidence > 1.0, unknown CapsuleType |
| `chain_violation` | Chain rules (CPS Section 4) are violated | Genesis with previous_hash, non-genesis without it |
| `integrity_violation` | Stored hash does not match content | Tampered domain with original hash |

### Invalid capsule conformance check

For every fixture:

1. Attempt to validate the capsule
2. Confirm the validator rejects it with an appropriate error
3. For `integrity_violation` fixtures, verify that `VerifyHash(capsule_dict, claimed_hash)` returns false

---

## Adding New Fixtures

New fixtures must be added through the [protocol change proposal](https://github.com/quantumpipes/capsule/issues/new?template=spec-change.md) process. Every new fixture must:

1. Test a specific edge case in the canonical serialization rules
2. Be deterministic (no random data)
3. Include `capsule_dict`, `canonical_json`, and `sha3_256_hash`
4. Be reviewed by at least one maintainer

---

*The conformance suite is the contract. Pass the fixtures, and you're compatible with every other implementation.*
