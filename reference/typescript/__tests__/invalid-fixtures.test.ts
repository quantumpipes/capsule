/**
 * Invalid capsule conformance (conformance/invalid-fixtures.json).
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { validateCapsuleDict } from "../src/validation.js";

const INVALID_PATH = resolve(__dirname, "../../../conformance/invalid-fixtures.json");
const invalidData = JSON.parse(readFileSync(INVALID_PATH, "utf-8")) as {
  fixtures: Array<{
    name: string;
    expected_error: string;
    error_field: string;
    capsule_dict: Record<string, unknown>;
    claimed_hash?: string;
  }>;
};

const GOLDEN_PATH = resolve(__dirname, "../../../conformance/fixtures.json");
const goldenData = JSON.parse(readFileSync(GOLDEN_PATH, "utf-8")) as {
  fixtures: Array<{ name: string; capsule_dict: Record<string, unknown> }>;
};

describe("invalid-fixtures.json (FR-002)", () => {
  it("has 16 fixtures", () => {
    expect(invalidData.fixtures).toHaveLength(16);
  });

  it.each(invalidData.fixtures)(
    "rejects $name",
    (fixture) => {
      const r = validateCapsuleDict(fixture.capsule_dict, {
        claimedHash: fixture.claimed_hash,
      });
      expect(r.ok, fixture.name).toBe(false);
      expect(r.category).toBe(fixture.expected_error);
      expect(r.field).toBe(fixture.error_field);
    },
  );
});

describe("golden fixtures pass validation", () => {
  it.each(goldenData.fixtures)("$name is valid", (f) => {
    const r = validateCapsuleDict(f.capsule_dict);
    expect(r.ok).toBe(true);
  });
});
