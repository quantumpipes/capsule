/**
 * Golden fixture conformance tests.
 *
 * Loads the CPS v1.0 golden test vectors from conformance/fixtures.json and
 * verifies the TypeScript implementation produces byte-identical canonical
 * JSON and matching SHA3-256 hashes for every vector.
 *
 * A conformant CPS implementation in any language must pass these fixtures.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { canonicalize } from "../src/canonical.js";
import { computeHashFromDict } from "../src/seal.js";

const FIXTURES_PATH = resolve(__dirname, "../../../conformance/fixtures.json");
const fixturesData = JSON.parse(readFileSync(FIXTURES_PATH, "utf-8"));
const fixtures: Array<{
  name: string;
  capsule_dict: Record<string, unknown>;
  canonical_json: string;
  sha3_256_hash: string;
}> = fixturesData.fixtures;

describe("Golden Fixture Conformance (CPS v1.0)", () => {
  it("should have exactly 16 fixtures", () => {
    expect(fixtures).toHaveLength(16);
  });

  it("should have unique fixture names", () => {
    const names = fixtures.map((f) => f.name);
    expect(new Set(names).size).toBe(names.length);
  });

  describe.each(fixtures)("$name", (fixture) => {
    it("produces byte-identical canonical JSON", () => {
      const actual = canonicalize(fixture.capsule_dict);
      expect(actual).toBe(fixture.canonical_json);
    });

    it("produces matching SHA3-256 hash", () => {
      const actual = computeHashFromDict(fixture.capsule_dict);
      expect(actual).toBe(fixture.sha3_256_hash);
    });

    it("hash is derived from canonical JSON", () => {
      const canonical = canonicalize(fixture.capsule_dict);
      const fromCanonical = computeHashFromDict(
        JSON.parse(canonical) as Record<string, unknown>,
      );
      expect(fromCanonical).toBe(fixture.sha3_256_hash);
    });
  });
});
