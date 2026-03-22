/**
 * Unit tests for validateCapsuleDict (FR-002), beyond invalid-fixtures.json table tests.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { validateCapsuleDict } from "../src/validation.js";

const GOLDEN_PATH = resolve(__dirname, "../../../conformance/fixtures.json");

function minimalGoldenDict(): Record<string, unknown> {
  const data = JSON.parse(readFileSync(GOLDEN_PATH, "utf-8")) as {
    fixtures: Array<{ name: string; capsule_dict: Record<string, unknown> }>;
  };
  const m = data.fixtures.find((f) => f.name === "minimal");
  if (!m) throw new Error("minimal fixture missing");
  return structuredClone(m.capsule_dict);
}

describe("validateCapsuleDict (FR-002)", () => {
  it("accepts minimal golden vector", () => {
    const d = minimalGoldenDict();
    const r = validateCapsuleDict(d);
    expect(r.ok).toBe(true);
    expect(r.category).toBeNull();
  });

  it("rejects empty object", () => {
    const r = validateCapsuleDict({});
    expect(r.ok).toBe(false);
    expect(r.category).toBe("missing_field");
    expect(r.field).toBe("id");
  });

  it("strictUnknownKeys rejects extra top-level key", () => {
    const d = minimalGoldenDict();
    const bad = { ...d, extra_field: 1 };
    const r = validateCapsuleDict(bad, { strictUnknownKeys: true });
    expect(r.ok).toBe(false);
    expect(r.field).toBe("extra_field");
    expect(r.category).toBe("invalid_value");
  });

  it("claimedHash mismatch yields integrity_violation", () => {
    const d = minimalGoldenDict();
    const r = validateCapsuleDict(d, {
      claimedHash: "a".repeat(64),
    });
    expect(r.ok).toBe(false);
    expect(r.category).toBe("integrity_violation");
    expect(r.field).toBe("hash");
  });

  it("claimedHash matching computeHashFromDict passes", () => {
    const data = JSON.parse(readFileSync(GOLDEN_PATH, "utf-8")) as {
      fixtures: Array<{ name: string; capsule_dict: Record<string, unknown>; sha3_256_hash: string }>;
    };
    const minimal = data.fixtures.find((f) => f.name === "minimal");
    if (!minimal) throw new Error("minimal missing");
    const r = validateCapsuleDict(minimal.capsule_dict, {
      claimedHash: minimal.sha3_256_hash,
    });
    expect(r.ok).toBe(true);
  });

  it("rejects root that is not a plain object", () => {
    const r = validateCapsuleDict(null);
    expect(r.ok).toBe(false);
    expect(r.category).toBe("wrong_type");
  });
});
