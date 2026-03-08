# Capsule URI Scheme

**Version**: 1.0
**Status**: Active
**Last Updated**: 2026-03-07

---

## Overview

The `capsule://` URI scheme provides content-addressable references to individual Capsule records. Every sealed Capsule has a SHA3-256 hash that uniquely identifies its content. The URI scheme formalizes this into a globally resolvable, self-verifying identifier.

```
capsule://sha3_4cb02d65a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef12
```

The hash in the URI is the verification. If you have the Capsule content and the hash matches, the content is authentic. No registry required.

---

## Syntax

```
capsule-uri     = "capsule://" authority "/" reference
authority       = chain-id / empty
reference       = hash-ref / sequence-ref / id-ref

hash-ref        = "sha3_" 64HEXDIG
sequence-ref    = 1*DIGIT
id-ref          = uuid

chain-id        = 1*( ALPHA / DIGIT / "-" / "_" / "." )
uuid            = 8HEXDIG "-" 4HEXDIG "-" 4HEXDIG "-" 4HEXDIG "-" 12HEXDIG
```

### URI Forms

| Form | Example | Resolves By |
|---|---|---|
| **Hash reference** | `capsule://sha3_4cb02d65...` | Content hash (globally unique) |
| **Chain + sequence** | `capsule://deploy-bot/42` | Chain context + sequence number |
| **Chain + hash** | `capsule://deploy-bot/sha3_4cb02d65...` | Chain context + content hash |
| **ID reference** | `capsule://a1b2c3d4-e5f6-7890-abcd-ef1234567890` | Capsule UUID |

### Examples

```
# Reference by content hash (most portable, self-verifying)
capsule://sha3_4cb02d65a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef12

# Reference within a named chain
capsule://deploy-bot/42
capsule://deploy-bot/sha3_4cb02d65...

# Reference by UUID
capsule://a1b2c3d4-e5f6-7890-abcd-ef1234567890

# Reference into a section (fragment)
capsule://sha3_4cb02d65...#reasoning
capsule://sha3_4cb02d65...#reasoning/confidence
capsule://sha3_4cb02d65...#execution/tool_calls/0
```

---

## Fragment Syntax

Fragments reference into the 6-section structure of a Capsule using JSON Pointer (RFC 6901) syntax after the `#`:

```
capsule-fragment = "#" json-pointer
json-pointer     = "/" reference-token *( "/" reference-token )
reference-token  = section-name / field-name / array-index

section-name     = "trigger" / "context" / "reasoning" / "authority" / "execution" / "outcome"
array-index      = 1*DIGIT
```

| Fragment | Resolves To |
|---|---|
| `#trigger` | The entire Trigger section |
| `#reasoning/confidence` | The confidence score |
| `#execution/tool_calls/0` | The first tool call |
| `#outcome/status` | The outcome status |

Fragments do not affect the URI's identity. `capsule://sha3_abc...` and `capsule://sha3_abc...#reasoning` reference the same Capsule; the fragment selects a view into it.

---

## Semantics

### Content Addressability

The `sha3_` prefix in hash references indicates the hash algorithm. This enables future algorithm agility:

| Prefix | Algorithm | Standard | Hash Length |
|---|---|---|---|
| `sha3_` | SHA3-256 | FIPS 202 | 64 hex characters |

CPS v1.0 uses SHA3-256 exclusively. Future CPS versions may introduce additional algorithms. The prefix ensures URIs remain unambiguous.

### Self-Verification

A `capsule://sha3_<hash>` URI is self-verifying:

1. Obtain the Capsule content (from any source)
2. Compute canonical JSON following CPS serialization rules
3. Compute SHA3-256 of the canonical JSON
4. Compare to the hash in the URI

If they match, the content is authentic. The URI itself is the verification key.

### Immutability

Once a Capsule is sealed and its hash computed, the `capsule://sha3_<hash>` URI is permanent. The content cannot change without changing the hash, which would be a different URI.

---

## Use Cases

### Cross-Agent Citation

An agent can reference another agent's decision in its reasoning:

```json
{
  "reasoning": {
    "analysis": "Based on deployment analysis capsule://sha3_7d2e9f41..., proceeding with rollback",
    "confidence": 0.95
  }
}
```

The cited Capsule is independently verifiable.

### Regulatory Evidence

Compliance reports can cite specific Capsule records:

> "The AI system's decision to deploy v2.4 was authorized by the operations lead, as recorded in `capsule://sha3_4cb02d65...#authority`."

### Chain Traversal

Starting from any Capsule, follow `previous_hash` to walk the chain:

```
capsule://sha3_C → previous_hash → capsule://sha3_B → previous_hash → capsule://sha3_A
```

### Parent-Child Linking

Workflow Capsules reference child Capsules:

```
capsule://sha3_workflow...  (parent_id: null)
  └── capsule://sha3_agent...  (parent_id: <workflow UUID>)
       └── capsule://sha3_tool...  (parent_id: <agent UUID>)
```

---

## Resolution

The URI scheme does not mandate a specific resolution mechanism. Implementations may resolve `capsule://` URIs through:

- **Local storage**: Query a `CapsuleStorage` backend by hash, sequence, or ID
- **HTTP gateway**: `GET https://api.example.com/capsules/sha3_4cb02d65...`
- **Peer-to-peer**: Content-addressed retrieval from a distributed network
- **File system**: Capsule stored as `sha3_4cb02d65...json` in a directory

The resolution mechanism is orthogonal to the URI scheme. The URI identifies; the transport resolves.

---

## Comparison to Other URI Schemes

| Scheme | Addresses | Verification | Mutable |
|---|---|---|---|
| `http://` | Location (server + path) | TLS (transport) | Yes |
| `git://` | Repository + ref | SHA-1/SHA-256 (content) | Refs are mutable, objects are not |
| `ipfs://` | Content (CID) | Multihash (content) | No |
| `capsule://` | AI action record (SHA3-256) | SHA3-256 + Ed25519 (content + signature) | No |

Capsule URIs are closest to IPFS CIDs in spirit: content-addressed, immutable, self-verifying. The key difference is that Capsule URIs also carry cryptographic signatures (Ed25519), providing authenticity in addition to integrity.

---

## Security Considerations

### URI Injection

Capsule URIs may appear in user-controlled fields (e.g., `reasoning.analysis`). Implementations that resolve URIs from untrusted content MUST:

1. **Validate the URI format** before resolution. Reject URIs that do not match the grammar in the Syntax section.
2. **Sanitize hash references**. The `sha3_` prefix must be followed by exactly 64 lowercase hex characters (`[0-9a-f]{64}`). Reject anything else.
3. **Bound resolution scope**. A URI resolver SHOULD only query storage backends the application explicitly configures. Never resolve against arbitrary external endpoints based on URI content.

### Resolution Trust Model

A `capsule://sha3_<hash>` URI is self-verifying: the content's hash must match the URI. However, **resolution** (obtaining the content) may be untrusted:

| Resolution Source | Trust Level | Verification Required |
|---|---|---|
| Local storage | Trusted (application controls storage) | Hash check sufficient |
| HTTP gateway | Untrusted (network-sourced) | Hash check + signature verification |
| Peer-to-peer | Untrusted | Hash check + signature verification + public key pinning |
| User-supplied | Untrusted | Full verification before any processing |

Implementations MUST verify the SHA3-256 hash of any content obtained from untrusted sources against the hash in the URI. If the hash does not match, the content MUST be rejected.

### Denial of Service

URI resolvers SHOULD implement:

- **Timeout** on resolution attempts (recommended: 5 seconds)
- **Size limit** on resolved content (recommended: 1 MB per Capsule)
- **Rate limiting** on resolution requests per client
- **Circuit breaking** on repeatedly failing resolution targets

### Fragment Safety

Fragments (`#reasoning/confidence`) select into the Capsule structure using JSON Pointer syntax. Implementations MUST validate that fragment paths conform to the 6-section structure and reject paths that attempt to traverse outside the Capsule (e.g., `#../../etc/passwd` is not a valid section name and must be rejected).

### No Ambient Authority

A `capsule://` URI MUST NOT grant any capability beyond read access to the referenced Capsule content. URIs are identifiers, not authorization tokens. Access control is the responsibility of the resolution layer, not the URI scheme.

---

*Feedback welcome via [protocol change proposal](https://github.com/quantumpipes/capsule/issues/new?template=spec-change.md).*
