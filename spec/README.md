# Capsule Protocol Specification (CPS)

**Version**: 1.0
**Status**: Active
**Last Updated**: 2026-03-23

---

## Purpose

This specification defines the **exact byte-level serialization** of a Capsule for cryptographic operations. Any implementation in any language that follows this specification will produce identical hashes for identical capsules, enabling cross-language sealing and verification.

The canonical form is the single point of truth for the entire cryptographic chain of trust: `Capsule → Canonical JSON → SHA3-256 → Ed25519`.

---

## 1. Capsule Structure

A Capsule is a JSON object with the following top-level keys (all required):

| Key | Type | Description |
|-----|------|-------------|
| `id` | string | Unique identifier for this Capsule. UUID v4, generated at creation time. |
| `type` | string | Category of AI action: `agent` (decision cycle), `tool` (tool invocation), `system` (internal event), `kill` (emergency stop), `workflow` (orchestration), `chat` (conversation turn), `vault` (document operation), `auth` (authentication event) |
| `domain` | string | Functional area or subsystem (default: `"agents"`). Enables filtering by business domain in multi-domain deployments. |
| `parent_id` | string \| null | Parent Capsule UUID for hierarchical linking (e.g., WORKFLOW → AGENT → TOOL), or null for top-level Capsules |
| `sequence` | integer | Position in the hash chain, 0-indexed. Genesis Capsule is 0, each subsequent Capsule increments by 1. |
| `previous_hash` | string \| null | SHA3-256 hex digest of the immediately preceding Capsule in the chain, or `null` for the genesis Capsule (sequence 0). This field creates the tamper-evident chain. |
| `spec_version` | string | CPS wire-format version for parse-time branching (e.g. `"1.0"`). **Included in the canonical content** hashed for SHA3-256. Parsers SHOULD treat records omitting this field as `"1.0"` for backward compatibility unless operating in strict mode. |
| `trigger` | object | [Trigger Section](#11-trigger-section) |
| `context` | object | [Context Section](#12-context-section) |
| `reasoning` | object | [Reasoning Section](#13-reasoning-section) |
| `authority` | object | [Authority Section](#14-authority-section) |
| `execution` | object | [Execution Section](#15-execution-section) |
| `outcome` | object | [Outcome Section](#16-outcome-section) |

### 1.1 Trigger Section

*What initiated this action?*

| Key | Type | Description |
|-----|------|-------------|
| `type` | string | How the action was initiated: `"user_request"` (human asked), `"scheduled"` (cron/timer), `"system"` (internal event), `"agent"` (another agent delegated) |
| `source` | string | Identity of who or what triggered the action — a user ID, agent name, service name, or scheduler name |
| `timestamp` | string | When the action was initiated, in ISO 8601 UTC (see [DateTime Format](#24-datetime-format)). Set at Capsule creation time, before execution begins. |
| `request` | string | The actual task, instruction, or query that initiated the action. For user requests, this is the user's message. For agent delegation, this is the delegated task description. |
| `correlation_id` | string \| null | Distributed tracing ID. Links related Capsules across services or systems in the same logical operation. All Capsules triggered by the same upstream request share this ID. |
| `user_id` | string \| null | Authenticated user identity, if the action was initiated by or on behalf of a human user. Null for system-initiated or agent-initiated actions. |

### 1.2 Context Section

*What was the state of the system when this action occurred?*

| Key | Type | Description |
|-----|------|-------------|
| `agent_id` | string | Identity of the agent performing the action. For multi-agent systems, this distinguishes which agent acted. |
| `session_id` | string \| null | Session or conversation group identifier. All Capsules with the same `session_id` belong to the same logical conversation, multi-turn chat, or workflow execution. Used to reconstruct the full context of a session from its constituent Capsules. |
| `environment` | object | System state at the time of action — cluster name, deployment region, model configuration, feature flags, or any contextual key-value pairs relevant to understanding *where* and *under what conditions* the action occurred. |

### 1.3 Reasoning Section

*Why was this decision made? Populated BEFORE execution begins — this is contemporaneous evidence of deliberation, not post-hoc justification.*

| Key | Type | Description |
|-----|------|-------------|
| `analysis` | string | The AI's initial assessment of the situation — what it observed, what it understood about the task, and what factors it considered before generating options. |
| `options` | array | Array of [ReasoningOption](#reasoning-option) objects — structured representations of each option the AI considered, with pros, cons, risks, and feasibility scores. |
| `options_considered` | array | Array of strings — shorthand list of option descriptions, for quick scanning without parsing the full `options` array. |
| `selected_option` | string | Which option the AI chose to execute. Must match one of the described options. |
| `reasoning` | string | The AI's rationale for selecting this option over the alternatives. This is the core "why" of the audit record. |
| `confidence` | number | The AI's self-assessed confidence in its decision, from 0.0 (no confidence) to 1.0 (certain). (**float-typed**, see [Float Rules](#23-float-typed-fields)) |
| `model` | string \| null | The AI model that made the decision (e.g., `"gpt-4o"`, `"claude-sonnet-4-20250514"`, `"llama3"`). Null if no AI model was involved. |
| `prompt_hash` | string \| null | SHA3-256 hash of the full prompt sent to the AI model. Enables prompt auditing without storing the full prompt in the Capsule (which may contain sensitive context). |

#### Reasoning Option

Each option the AI considered, with structured arguments for and against:

| Key | Type | Description |
|-----|------|-------------|
| `id` | string | Unique identifier for this option within the Capsule (e.g., `"opt_1"`, `"opt_2"`) |
| `description` | string | What this option entails — the action that would be taken |
| `pros` | array | Arguments in favor of this option |
| `cons` | array | Arguments against this option |
| `estimated_impact` | object | Projected impact — scope, severity, reversibility, cost, or any domain-specific impact dimensions |
| `feasibility` | number | How feasible the AI assessed this option to be, from 0.0 (impossible) to 1.0 (trivial). (**float-typed**) |
| `risks` | array | Known risks if this option is executed |
| `selected` | boolean | `true` for the chosen option, `false` for all others |
| `rejection_reason` | string | Why this option was NOT selected. Required for non-selected options — every rejected alternative must explain why it was rejected. |

### 1.4 Authority Section

*Who or what authorized this action? Answers the question: "Was the AI allowed to do this?"*

| Key | Type | Description |
|-----|------|-------------|
| `type` | string | How the action was authorized: `"autonomous"` (AI acted independently), `"human_approved"` (a human explicitly approved), `"policy"` (an automated policy rule permitted it), `"escalated"` (AI requested and received higher authority) |
| `approver` | string \| null | Identity of the human who approved, if `type` is `"human_approved"` or `"escalated"`. Null for autonomous or policy-based authorization. |
| `policy_reference` | string \| null | Identifier of the policy rule that authorized the action, if `type` is `"policy"`. Enables tracing the decision back to a specific governance rule. |
| `chain` | array | Multi-step approval chain — an ordered array of approval records, each documenting one step in a multi-level authorization flow (e.g., agent requests → team lead approves → security reviews) |
| `escalation_reason` | string \| null | Why the action required escalation beyond normal authority. Null when no escalation occurred. |

### 1.5 Execution Section

*What actually happened? Records every tool invocation, its inputs, outputs, and timing.*

| Key | Type | Description |
|-----|------|-------------|
| `tool_calls` | array | Ordered array of [ToolCall](#tool-call) objects — every external action the AI performed, in execution order |
| `duration_ms` | integer | Total wall-clock duration of the entire execution phase, in milliseconds |
| `resources_used` | object | Resources consumed during execution — token counts, API costs, compute time, memory, or any measurable resource. Recommended keys: `tokens_in`, `tokens_out`, `cost_usd`, `latency_ms`. |

#### Tool Call

Each external action the AI performed:

| Key | Type | Description |
|-----|------|-------------|
| `tool` | string | Name of the tool or function that was called (e.g., `"kubectl_apply"`, `"web_search"`, `"file_read"`) |
| `arguments` | object | The input arguments passed to the tool, as key-value pairs |
| `result` | any | The tool's output — any JSON type (string, object, array, number, boolean, null) |
| `success` | boolean | Whether the tool call completed successfully |
| `duration_ms` | integer | How long this individual tool call took, in milliseconds |
| `error` | string \| null | Error message if the tool call failed. Null on success. |

### 1.6 Outcome Section

*What was the result? What changed in the world because of this action?*

| Key | Type | Description |
|-----|------|-------------|
| `status` | string | Final status: `"pending"` (not yet complete), `"success"` (completed as intended), `"failure"` (completed with error), `"partial"` (partially completed), `"blocked"` (prevented by policy, kill switch, or authorization failure) |
| `result` | any | Detailed, machine-readable result — any JSON type. For successful actions, the output data. For failures, diagnostic information. |
| `summary` | string | Human-readable one-line summary of what happened, suitable for display in an audit log or dashboard |
| `error` | string \| null | Error message if the action failed or was blocked. Null on success. |
| `side_effects` | array | What changed in the external world — descriptions of state mutations, deployments, file changes, notifications sent, or any observable effect (e.g., `"deployment/web replicas: 4 → 6"`) |
| `metrics` | object | Performance and quality metrics for this action. Recommended keys: `tokens_in`, `tokens_out`, `latency_ms`, `cost_usd`, `quality_score`. |

---

## 2. Canonical JSON Serialization Rules

The canonical form transforms a Capsule object into a deterministic byte string. All implementations MUST produce byte-identical output for the same logical Capsule.

### 2.1 Key Ordering

All object keys MUST be sorted **lexicographically by Unicode code point**, applied **recursively** to all nested objects.

This includes:
- Top-level Capsule keys
- Section keys (trigger, context, etc.)
- Keys within `environment`, `resources_used`, `metrics`, `result` (if object), `arguments`, `estimated_impact`
- Keys within objects inside `chain` array elements

Array elements are NOT sorted — their order is preserved.

### 2.2 Whitespace

Zero whitespace. No spaces after `:` or `,`. No newlines.

Equivalent to Python's `json.dumps(separators=(",", ":"))`.

### 2.3 Float-Typed Fields

The following fields are **float-typed** and MUST always be serialized with at least one decimal place, even when the value is mathematically an integer:

| Field Path | Example |
|------------|---------|
| `reasoning.confidence` | `0.0`, `0.95`, `1.0` |
| `reasoning.options[].feasibility` | `0.0`, `0.5`, `1.0` |

Rules for float-typed fields:
- `0.0` → `0.0` (NOT `0`)
- `1.0` → `1.0` (NOT `1`)
- `0.95` → `0.95`
- `Infinity` and `NaN` are PROHIBITED (raise an error)

All other numeric values (integers in `duration_ms`, `sequence`, values in arbitrary dicts) follow standard JSON number formatting:
- `0` → `0`
- `42` → `42`

**Rationale**: Python's `json.dumps` preserves the float/int distinction from the Python type system. The float-typed fields in the Capsule data model are defined as `float` in the Python reference implementation, so they always serialize with a decimal point. Other languages (JavaScript, Go) do not distinguish floats from integers; implementations in those languages must explicitly format these fields.

### 2.4 DateTime Format

The `trigger.timestamp` field uses Python's `datetime.isoformat()` output format for UTC datetimes:

```
YYYY-MM-DDTHH:MM:SS+00:00
```

Examples:
- `2026-01-01T00:00:00+00:00` (correct)
- `2026-01-01T00:00:00Z` (INCORRECT — do not use `Z` suffix)
- `2026-01-01T00:00:00.000+00:00` (INCORRECT — no fractional seconds unless present in source)

When fractional seconds are present:
- `2026-01-01T12:30:45.123456+00:00` (correct — preserve microseconds from source)

### 2.5 UUID Format

UUIDs MUST be serialized as lowercase hexadecimal with hyphens:

```
xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

Example: `12345678-1234-1234-1234-123456789012`

### 2.6 String Escaping

Strings follow RFC 8259 (JSON) escaping rules. Characters that MUST be escaped:
- `"` → `\"`
- `\` → `\\`
- Control characters (U+0000 through U+001F) → `\uXXXX`

Characters that MUST NOT be escaped:
- `/` (solidus) — serialize as literal `/`, not `\/`
- Printable ASCII (U+0020 through U+007E) — serialize as literal characters
- Non-ASCII Unicode (U+0080 and above) — serialize as literal UTF-8 characters, NOT as `\uXXXX` escapes

This matches the default behavior of Go (`json.Marshal`), Rust (`serde_json`), and TypeScript (`JSON.stringify`). In Python, use `json.dumps(..., ensure_ascii=False)`.

### 2.7 Null, Boolean, and Empty Collections

| Value | Serialized |
|-------|------------|
| null | `null` |
| true | `true` |
| false | `false` |
| empty array | `[]` |
| empty object | `{}` |

---

## 3. Sealing Algorithm

### 3.1 Hash Computation

```
INPUT:  Capsule object
OUTPUT: 64-character lowercase hex string

1. Convert Capsule to dict via to_dict()
2. Serialize to canonical JSON following all rules in Section 2
3. Encode canonical JSON as UTF-8 bytes
4. Compute SHA3-256 (FIPS 202) of the bytes
5. Return lowercase hexadecimal digest
```

### 3.2 Ed25519 Signature (Required)

```
INPUT:  SHA3-256 hex digest (64-character ASCII string)
OUTPUT: 128-character hex string

1. Encode the hex digest string as UTF-8 bytes (64 bytes of ASCII)
   NOTE: Sign the hex STRING, not the raw 32-byte hash
2. Sign with Ed25519 (RFC 8032) using the private key
3. Return lowercase hexadecimal signature
```

**Critical detail**: The Ed25519 signature is computed over the **hex-encoded hash string** (64 ASCII characters encoded as UTF-8), not the raw 32-byte hash value. This is intentional and must be replicated exactly.

### 3.3 ML-DSA-65 Signature (Optional)

```
INPUT:  SHA3-256 hex digest (64-character ASCII string)
OUTPUT: hex string

1. Encode the hex digest string as UTF-8 bytes
2. Sign with ML-DSA-65 (FIPS 204) / Dilithium3 using the private key
3. Return lowercase hexadecimal signature
```

### 3.4 Verification

```
INPUT:  Capsule with hash and signature fields populated
OUTPUT: boolean

1. Extract hash and signature from Capsule
2. Clear hash, signature, signature_pq, signed_at, signed_by fields
   (these are NOT part of the canonical content)
3. Recompute canonical JSON from the Capsule content
4. Compute SHA3-256 of canonical JSON
5. Compare computed hash with stored hash (must match exactly)
6. Verify Ed25519 signature over the stored hash string using public key
7. Return true only if both hash and signature verify
```

Note: The seal fields (`hash`, `signature`, `signature_pq`, `signed_at`, `signed_by`) are metadata OUTSIDE the canonical content. The `to_dict()` method does not include them. Verification recomputes canonical JSON from the content fields only.

---

## 4. Hash Chain Rules

1. The first Capsule (genesis) has `sequence: 0` and `previous_hash: null`
2. Each subsequent Capsule has `sequence: N+1` and `previous_hash` equal to the `hash` of the Capsule at sequence N
3. Sequence numbers MUST be consecutive with no gaps
4. Chain verification checks: consecutive sequences, hash linkage, and genesis has null previous_hash

---

## 5. Golden Test Vectors

See [`conformance/fixtures.json`](../conformance/fixtures.json) for test vectors that all implementations must pass. Each vector contains:

- `capsule_dict`: The Capsule as a JSON object (output of `to_dict()`)
- `canonical_json`: The exact canonical JSON string
- `sha3_256_hash`: The expected SHA3-256 hex digest

An implementation is conformant if, for every test vector, it produces byte-identical `canonical_json` and `sha3_256_hash` from the `capsule_dict` input.

---

## 6. Implementation Checklist

For a conformant implementation in any language:

- [ ] Capsule data model with all 6 sections and all fields
- [ ] `to_dict()` — convert Capsule to a plain dictionary/map
- [ ] `canonicalize()` — serialize dict to canonical JSON (Section 2)
- [ ] `compute_hash()` — SHA3-256 of canonical JSON
- [ ] `seal()` — compute hash + Ed25519 signature
- [ ] `verify()` — recompute hash and verify signature
- [ ] `from_dict()` — deserialize Capsule from dictionary/map
- [ ] Pass all golden test vectors from `fixtures.json`
- [ ] Chain verification (sequence + hash linkage)

---

## 7. Security Considerations

### 7.1 What CPS Provides

| Property | Mechanism | Strength |
|---|---|---|
| **Integrity** | SHA3-256 content hash | Any modification changes the hash |
| **Authenticity** | Ed25519 signature | Proves which key signed the record |
| **Non-repudiation** | Signature + `signed_by` fingerprint | Third-party verification via `verify_with_key()` |
| **Temporal ordering** | Hash chain (`previous_hash` + `sequence`) | Insertion, deletion, and reordering are detectable |
| **Quantum resistance** | Optional ML-DSA-65 dual signature | FIPS 204, additive to Ed25519 |

### 7.2 What CPS Does Not Provide

| Property | Reason |
|---|---|
| **Confidentiality** | Capsule content is plaintext JSON. The protocol provides integrity, not encryption. Field-level encryption is a deployment concern. |
| **Content truthfulness** | The seal proves a record has not been modified after creation. It does not prove the content was accurate when created. A compromised or misaligned agent can record fabricated reasoning that passes all cryptographic checks. |
| **Availability** | The protocol cannot force an application to create Capsules. If the runtime is compromised, it may skip record creation entirely. The chain shows no gap because the record was never created. |
| **Identity binding** | `signed_by` contains a key fingerprint, not an identity. The protocol does not bind keys to agents, organizations, or runtimes. Whoever holds the private key IS the signer. |

### 7.3 Signer Key Compromise

If an attacker obtains the Ed25519 private key, they can forge Capsules that are indistinguishable from legitimate ones. Past Capsules remain valid. Mitigations:

- Restrict key file permissions (reference implementation uses `0600` with `umask(0o077)`)
- Use HSM-bound keys in production to prevent extraction
- Rotate keys periodically; use `verify_with_key()` for old keys
- Enable ML-DSA-65 dual signatures so both algorithms must be compromised

The protocol does not include key revocation or expiration. These are deployment-layer concerns.

### 7.4 Chain Truncation

If an attacker deletes the last N records from storage, the truncated chain still verifies as valid from genesis to the truncation point. The protocol has no "expected chain length" anchor. Mitigations:

- Monitor chain length externally (compare expected vs. actual)
- Periodically checkpoint chain head hashes to an independent system
- Use append-only storage (e.g., S3 Object Lock, WORM storage)

### 7.5 Chain Verification Levels

Chain verification has two levels. Implementations SHOULD support both:

1. **Structural verification** (fast): Check sequence numbers and `previous_hash` linkage. This trusts stored hash values without recomputing them.
2. **Cryptographic verification** (thorough): Recompute SHA3-256 from content for each record and optionally verify Ed25519 signatures. This detects storage-level content tampering.

Structural verification alone does not detect an attacker who modifies both content and the stored hash. Cryptographic verification catches this because the signature will not match the recomputed hash (unless the signing key is also compromised).

### 7.6 Replay

A sealed Capsule is valid regardless of where it is stored. An attacker who copies a valid chain to a different storage backend creates a valid chain. The protocol does not bind chains to storage locations. Mitigations:

- Use `tenant_id` scoping to isolate chains
- Verify chain provenance via external metadata (storage origin, deployment context)

### 7.7 Timestamp Trust

`trigger.timestamp` and `signed_at` are set by the creating application, not by a trusted time source. An application could backdate or future-date timestamps. The hash chain provides relative ordering (Capsule N was sealed after Capsule N-1), but absolute timestamps are only as trustworthy as the runtime clock.

---

## 8. Key Management Recommendations

The CPS does not mandate a specific key management implementation. The following are recommendations for conformant implementations.

### 8.1 Epoch-Based Rotation

Implementations SHOULD support key rotation through an *epoch* model:

- Each epoch represents a single Ed25519 key pair with a lifecycle: **active**, **retired**
- At any time, exactly one epoch is active (used for signing new Capsules)
- Retired epochs retain their public key for verification of previously-signed Capsules
- The private key from a retired epoch SHOULD be securely deleted

### 8.2 Keyring

Implementations SHOULD maintain a keyring file (or equivalent) that maps fingerprints to public keys across epochs. This enables verification of Capsules signed by any epoch without manual key management.

### 8.3 Backward-Compatible Verification

When verifying a sealed Capsule, implementations SHOULD:

1. Read the Capsule's `signed_by` fingerprint
2. Look up the corresponding public key in the keyring
3. Verify the Ed25519 signature with the resolved key
4. Fall back to the local active key if the fingerprint is not found

This allows a single verifier to validate Capsules from any epoch.

### 8.4 NIST SP 800-57 Alignment

| Lifecycle Phase | Recommendation |
|---|---|
| Generation | Generate Ed25519 key pair using cryptographically secure random |
| Active | Use for new Capsule signatures |
| Retired | Retain public key in keyring; delete private key |
| Destroyed | Overwrite private key file on rotation |

### 8.5 Fingerprints

Implementations SHOULD identify signing keys by a short fingerprint derived from the public key. The Python reference uses the format `qp_key_XXXX` (first 4 hex characters of the public key). Implementations MAY use different fingerprint formats but MUST ensure fingerprints are unique within a keyring.

---

## 9. URI Scheme

Capsules are content-addressable via the `capsule://` URI scheme. Every sealed Capsule can be referenced by its SHA3-256 hash:

```
capsule://sha3_<64-character-hex-digest>
```

See [URI Scheme](./uri-scheme.md) for the full specification.

---

## Related Documents

| Document | Description |
|---|---|
| [URI Scheme](./uri-scheme.md) | `capsule://` content-addressable URI scheme |
| [Conformance Suite](../conformance/) | 16 golden test vectors |
| [Python Reference](../reference/python/) | Python reference implementation |
| [TypeScript Reference](../reference/typescript/) | TypeScript reference implementation |

---

*This specification is the contract. Pass the golden fixtures, and you're compatible with every other implementation.*
