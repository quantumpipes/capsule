# Capsule Protocol — TypeScript Reference Implementation

> **Status**: Conformant — 16/16 golden fixtures passing, 101 tests, 100% coverage

TypeScript reference implementation of the [Capsule Protocol Specification (CPS)](../../spec/). Create, seal, verify, and chain Capsules in TypeScript/JavaScript.

---

## Install

```bash
npm install @quantumpipes/capsule
```

Requires Node.js >= 20.19.0.

---

## Quick Start

```typescript
import { createCapsule, seal, verify, generateKeyPair } from "@quantumpipes/capsule";

const capsule = createCapsule({
  type: "agent",
  trigger: {
    type: "user_request",
    source: "deploy-bot",
    timestamp: new Date().toISOString().replace("Z", "+00:00"),
    request: "Deploy service v2.4 to production",
    correlation_id: null,
    user_id: null,
  },
});

const { privateKey, publicKey } = generateKeyPair();
const pub = await publicKey;

await seal(capsule, privateKey);
const valid = await verify(capsule, pub);
console.log(`Sealed: ${capsule.hash.slice(0, 16)}... Valid: ${valid}`);
```

---

## API

### Capsule Model

| Export | Description |
|---|---|
| `createCapsule(partial?)` | Create a Capsule with defaults for all 6 sections |
| `toDict(capsule)` | Extract content dict (excludes seal fields) |
| `isSealed(capsule)` | Check if hash and signature are present |
| Factory functions | `createTrigger`, `createContext`, `createReasoning`, `createAuthority`, `createExecution`, `createOutcome` |

### Canonical Serialization

| Export | Description |
|---|---|
| `canonicalize(value)` | CPS Section 2 compliant canonical JSON |

### Cryptographic Seal

| Export | Description |
|---|---|
| `computeHash(capsuleDict)` | SHA3-256 of canonical JSON (64-char hex) |
| `seal(capsule, privateKey)` | Hash + Ed25519 sign |
| `verify(capsule, publicKey)` | Recompute hash + verify signature |
| `generateKeyPair()` | Ed25519 key pair generation |
| `getFingerprint(privateKey)` | Public key fingerprint (16 hex chars) |

### Chain Verification

| Export | Description |
|---|---|
| `verifyChain(capsules)` | Validate sequence numbers and hash linkage |

---

## Crypto Libraries

| Capability | Library | Version |
|---|---|---|
| SHA3-256 | `@noble/hashes` | ^2.0.1 |
| Ed25519 | `@noble/ed25519` | ^3.0.0 |

Both are audited, zero-dependency, pure-JS implementations by Paul Miller.

---

## Conformance

This implementation passes all 16 golden test vectors from [`conformance/fixtures.json`](../../conformance/fixtures.json).

```bash
npm test    # 101 tests: 47 conformance + 22 canonical + 15 capsule + 11 seal + 6 chain
```

### Known TypeScript Pitfalls (CPS Section 2)

- `JSON.stringify` does not distinguish float from integer -- `confidence: 1.0` serializes as `1`, but the protocol requires `1.0`. The `canonicalize()` function handles this via float-path detection.
- DateTime format must use `+00:00`, not `Z`.
- Non-ASCII Unicode must serialize as literal UTF-8, not `\uXXXX`.

---

## Development

```bash
cd reference/typescript
npm install
npm run build
npm test
```

---

## License

[Apache License 2.0](../../LICENSE) with [additional patent grant](../../PATENTS.md).
