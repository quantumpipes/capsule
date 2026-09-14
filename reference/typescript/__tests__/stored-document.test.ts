/**
 * Verification hashes the stored document (CPS Section 3.5).
 *
 * A record read back from storage is verified against the exact content document that
 * was sealed, not a re-serialization of today's model. Records sealed before a content
 * field existed keep verifying, and anything stored beside the sealed content is caught.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import {
  ADDED_CONTENT_DEFAULTS,
  contentForHash,
  createCapsule,
  storedDocument,
  toDict,
  withStoredDocument,
  type Capsule,
} from "../src/capsule.js";
import { verifyChain } from "../src/chain.js";
import { computeHashFromDict, generateKeyPair, seal, verifyDetailed } from "../src/seal.js";

const FIXTURES_PATH = resolve(__dirname, "../../../conformance/stored-document-fixtures.json");
const vector = JSON.parse(readFileSync(FIXTURES_PATH, "utf-8")).fixtures[0];

const SEAL_FIELDS = ["hash", "signature", "signature_pq", "signed_at", "signed_by"];

/** Read a sealed record the way a storage layer would: fill defaults, remember the document. */
function readSealedRecord(record: Record<string, unknown>): Capsule {
  const document: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(record)) {
    if (!SEAL_FIELDS.includes(key)) document[key] = value;
  }
  const capsule = { ...ADDED_CONTENT_DEFAULTS, ...structuredClone(record) } as unknown as Capsule;
  return withStoredDocument(capsule, document);
}

/** A capsule whose stored document is a copy of its own content. */
function loaded(): { capsule: Capsule; document: Record<string, unknown> } {
  const capsule = createCapsule({ type: "agent" });
  capsule.reasoning.options_considered = ["a", "b"];
  const document = structuredClone(toDict(capsule)) as unknown as Record<string, unknown>;
  withStoredDocument(capsule, document);
  return { capsule, document };
}

describe("records sealed before spec_version", () => {
  it("verify against the stored document", async () => {
    const capsule = readSealedRecord(vector.sealed_record);
    const result = await verifyDetailed(capsule, hexToBytes(vector.public_key_hex));
    expect(result).toEqual({ ok: true, code: "ok", message: "" });
  });

  it("hash differently when re-serialized from the model", () => {
    const capsule = readSealedRecord(vector.sealed_record);
    expect(computeHashFromDict(toDict(capsule) as unknown as Record<string, unknown>)).toBe(
      vector.model_sha3_256_hash,
    );
    expect(vector.model_sha3_256_hash).not.toBe(vector.sha3_256_hash);
  });

  it("fail when the stored document is forgotten", async () => {
    const capsule = withStoredDocument(readSealedRecord(vector.sealed_record), null);
    const result = await verifyDetailed(capsule, hexToBytes(vector.public_key_hex));
    expect(result.code).toBe("hash_mismatch");
  });

  it("pass cryptographic chain verification", () => {
    const capsule = readSealedRecord(vector.sealed_record);
    expect(verifyChain([capsule], { verifyContent: true }).valid).toBe(true);
  });
});

describe("a capsule changed after it was read", () => {
  it("fails verifyDetailed", async () => {
    const capsule = readSealedRecord(vector.sealed_record);
    capsule.trigger.request = "Something else";
    const result = await verifyDetailed(capsule, hexToBytes(vector.public_key_hex));
    expect(result.code).toBe("hash_mismatch");
    expect(result.message).toContain("changed after it was read");
  });

  it("fails cryptographic chain verification", () => {
    const capsule = readSealedRecord(vector.sealed_record);
    capsule.outcome.summary = "edited";
    const result = verifyChain([capsule], { verifyContent: true });
    expect(result.valid).toBe(false);
    expect(result.error).toContain("Content hash mismatch");
  });

  it("verifies again once re-sealed, and forgets the stored document", async () => {
    const { privateKey, publicKey } = generateKeyPair();
    const capsule = readSealedRecord(vector.sealed_record);
    capsule.trigger.request = "Something else";
    await seal(capsule, privateKey);
    expect(storedDocument(capsule)).toBeUndefined();
    expect((await verifyDetailed(capsule, await publicKey)).ok).toBe(true);
  });
});

describe("verifyDetailed error handling", () => {
  it("reports a hash mismatch when the stored document cannot be serialized", async () => {
    const { privateKey, publicKey } = generateKeyPair();
    const capsule = createCapsule({ type: "agent" });
    await seal(capsule, privateKey);
    const loop: Record<string, unknown> = {};
    loop.self = loop;
    withStoredDocument(capsule, {
      ...(structuredClone(toDict(capsule)) as unknown as Record<string, unknown>),
      loop,
    });
    const result = await verifyDetailed(capsule, await publicKey);
    expect(result.code).toBe("hash_mismatch");
    expect(result.message).toContain("could not compute content hash");
  });

  it("reports an Ed25519 verification error for an unusable public key", async () => {
    const { privateKey } = generateKeyPair();
    const capsule = createCapsule({ type: "agent" });
    await seal(capsule, privateKey);
    const result = await verifyDetailed(capsule, undefined as unknown as Uint8Array);
    expect(result.code).toBe("invalid_signature");
    expect(result.message).toContain("Ed25519 verification error");
  });
});

describe("agreement between the model and the stored document", () => {
  it("a fresh capsule hashes its model", () => {
    const capsule = createCapsule({ type: "tool" });
    expect(contentForHash(capsule)).toEqual(toDict(capsule));
  });

  it("an agreeing model yields the stored document", () => {
    const { capsule, document } = loaded();
    expect(contentForHash(capsule)).toBe(document);
  });

  it("tolerates an added field that still holds its default", () => {
    const { capsule, document } = loaded();
    delete document.spec_version;
    expect(contentForHash(capsule)).toBe(document);
  });

  it("treats an added field with another value as a change", () => {
    const { capsule, document } = loaded();
    delete document.spec_version;
    capsule.spec_version = "2.0";
    expect(contentForHash(capsule)).toBeNull();
  });

  it("treats a missing field that was never added later as a change", () => {
    const { capsule, document } = loaded();
    delete document.domain;
    expect(contentForHash(capsule)).toBeNull();
  });

  it("applies added-field defaults only at the top level", () => {
    const { capsule, document } = loaded();
    delete (document.trigger as Record<string, unknown>).request;
    expect(contentForHash(capsule)).toBeNull();
  });

  it("treats a section replaced by a scalar as a change", () => {
    const { capsule, document } = loaded();
    document.trigger = "flattened";
    expect(contentForHash(capsule)).toBeNull();
  });

  it("treats a list length difference as a change", () => {
    const { capsule, document } = loaded();
    ((document.reasoning as Record<string, unknown>).options_considered as string[]).push("c");
    expect(contentForHash(capsule)).toBeNull();
  });

  it("treats a list replaced by a scalar as a change", () => {
    const { capsule, document } = loaded();
    (document.reasoning as Record<string, unknown>).options_considered = "a";
    expect(contentForHash(capsule)).toBeNull();
  });

  it("treats a list item difference as a change", () => {
    const { capsule, document } = loaded();
    ((document.reasoning as Record<string, unknown>).options_considered as string[])[0] = "z";
    expect(contentForHash(capsule)).toBeNull();
  });

  it("keeps extra stored keys in the hashed document, so injected content fails", async () => {
    const { privateKey, publicKey } = generateKeyPair();
    const capsule = createCapsule({ type: "agent" });
    await seal(capsule, privateKey);
    const document = { ...structuredClone(toDict(capsule)), injected: "unsigned" };
    withStoredDocument(capsule, document as unknown as Record<string, unknown>);
    expect(contentForHash(capsule)).toBe(document);
    expect((await verifyDetailed(capsule, await publicKey)).code).toBe("hash_mismatch");
  });

  it("treats a key holding undefined as absent", () => {
    const { capsule, document } = loaded();
    delete document.parent_id;
    (capsule as unknown as Record<string, unknown>).parent_id = undefined;
    expect(contentForHash(capsule)).toBe(document);
  });

  it("treats a stored nested key absent from the model as a change", () => {
    const { capsule, document } = loaded();
    (document.context as Record<string, unknown>).environment = { removed_in_memory: 1 };
    expect(contentForHash(capsule)).toBeNull();
  });

  it("fails chain verification when content cannot be hashed", () => {
    const capsule = readSealedRecord(vector.sealed_record);
    const loop: Record<string, unknown> = {};
    loop.self = loop;
    withStoredDocument(capsule, { ...(storedDocument(capsule) as Record<string, unknown>), loop });
    expect(verifyChain([capsule], { verifyContent: true }).valid).toBe(false);
  });

  it("keeps the stored document out of serialization and forgets it on request", () => {
    const { capsule } = loaded();
    expect(Object.keys(capsule)).not.toContain("storedDocument");
    expect(JSON.stringify(capsule)).not.toContain("qp.capsule.storedDocument");
    withStoredDocument(capsule, null);
    expect(storedDocument(capsule)).toBeUndefined();
  });
});
