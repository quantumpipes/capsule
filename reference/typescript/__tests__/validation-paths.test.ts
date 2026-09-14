/**
 * Every rejection path in validateCapsuleDict (FR-002), one mutation of the minimal
 * golden vector at a time.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { computeHashFromDict } from "../src/seal.js";
import { validateCapsuleDict } from "../src/validation.js";

const GOLDEN_PATH = resolve(__dirname, "../../../conformance/fixtures.json");
const UUID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const HASH = "ab".repeat(32);

function minimal(): Record<string, any> {
  const data = JSON.parse(readFileSync(GOLDEN_PATH, "utf-8")) as {
    fixtures: Array<{ name: string; capsule_dict: Record<string, unknown> }>;
  };
  return structuredClone(data.fixtures.find((f) => f.name === "minimal")!.capsule_dict);
}

type Case = [string, (d: Record<string, any>) => void, string, string];

const rejections: Case[] = [
  ["id is not a string", (d) => { d.id = 5; }, "wrong_type", "id"],
  ["id is not a UUID", (d) => { d.id = "not-a-uuid"; }, "invalid_value", "id"],
  ["type is not a string", (d) => { d.type = 5; }, "wrong_type", "type"],
  ["type is unknown", (d) => { d.type = "bogus"; }, "invalid_value", "type"],
  ["domain is not a string", (d) => { d.domain = 5; }, "wrong_type", "domain"],
  ["parent_id is not a string", (d) => { d.parent_id = 5; }, "wrong_type", "parent_id"],
  ["parent_id is not a UUID", (d) => { d.parent_id = "x"; }, "invalid_value", "parent_id"],
  ["sequence is not an integer", (d) => { d.sequence = 1.5; }, "wrong_type", "sequence"],
  ["sequence is not a number", (d) => { d.sequence = "1"; }, "wrong_type", "sequence"],
  ["sequence is negative", (d) => { d.sequence = -1; }, "invalid_value", "sequence"],
  ["previous_hash is not a string", (d) => { d.previous_hash = 5; }, "wrong_type", "previous_hash"],
  ["previous_hash is not hex", (d) => { d.previous_hash = "abc"; }, "invalid_value", "previous_hash"],
  ["spec_version is not a string", (d) => { d.spec_version = 5; }, "wrong_type", "spec_version"],
  ["spec_version is empty", (d) => { d.spec_version = ""; }, "invalid_value", "spec_version"],
  ["genesis carries previous_hash", (d) => { d.previous_hash = HASH; }, "chain_violation", "previous_hash"],
  ["non-genesis lacks previous_hash", (d) => { d.sequence = 1; }, "chain_violation", "previous_hash"],
  ["trigger is not an object", (d) => { d.trigger = "x"; }, "wrong_type", "trigger"],
  ["trigger type is null", (d) => { d.trigger.type = null; }, "wrong_type", "trigger.type"],
  ["trigger timestamp is not a string", (d) => { d.trigger.timestamp = 5; }, "wrong_type", "trigger.timestamp"],
  ["trigger timestamp has no timezone", (d) => { d.trigger.timestamp = "2026-01-15T12:00:00"; }, "invalid_value", "trigger.timestamp"],
  ["trigger timestamp ends in Z but is not a date", (d) => { d.trigger.timestamp = "notadateZ"; }, "invalid_value", "trigger.timestamp"],
  ["context is not an object", (d) => { d.context = "x"; }, "wrong_type", "context"],
  ["context.environment is not an object", (d) => { d.context.environment = []; }, "wrong_type", "context.environment"],
  ["reasoning is not an object", (d) => { d.reasoning = "x"; }, "wrong_type", "reasoning"],
  ["confidence is a boolean", (d) => { d.reasoning.confidence = true; }, "wrong_type", "reasoning.confidence"],
  ["confidence is a string", (d) => { d.reasoning.confidence = "0.5"; }, "wrong_type", "reasoning.confidence"],
  ["confidence is above 1", (d) => { d.reasoning.confidence = 1.5; }, "invalid_value", "reasoning.confidence"],
  ["authority is not an object", (d) => { d.authority = "x"; }, "wrong_type", "authority"],
  ["execution is not an object", (d) => { d.execution = "x"; }, "wrong_type", "execution"],
  ["tool_calls is not an array", (d) => { d.execution.tool_calls = "x"; }, "wrong_type", "execution.tool_calls"],
  ["duration_ms is not an integer", (d) => { d.execution.duration_ms = 1.5; }, "wrong_type", "execution.duration_ms"],
  ["resources_used is not an object", (d) => { d.execution.resources_used = []; }, "wrong_type", "execution.resources_used"],
  ["outcome is not an object", (d) => { d.outcome = "x"; }, "wrong_type", "outcome"],
];

describe("validateCapsuleDict rejection paths", () => {
  it.each([null, [], "capsule"])("rejects a root that is not an object: %j", (root) => {
    const r = validateCapsuleDict(root);
    expect(r.ok).toBe(false);
    expect(r.category).toBe("wrong_type");
  });

  it.each(rejections)("%s", (_name, mutate, category, field) => {
    const d = minimal();
    mutate(d);
    const r = validateCapsuleDict(d);
    expect(r.ok).toBe(false);
    expect(r.category).toBe(category);
    expect(r.field).toBe(field);
  });

  it.each(["trigger", "context", "reasoning", "authority", "execution", "outcome"])(
    "rejects an empty %s section as a missing field",
    (section) => {
      const d = minimal();
      d[section] = {};
      const r = validateCapsuleDict(d);
      expect(r.ok).toBe(false);
      expect(r.category).toBe("missing_field");
      expect(r.field?.startsWith(`${section}.`)).toBe(true);
    },
  );

  it("accepts a linked capsule with a UUID parent and a Z timestamp", () => {
    const d = minimal();
    d.parent_id = UUID;
    d.sequence = 1;
    d.previous_hash = HASH;
    d.trigger.timestamp = "2026-01-15T12:00:00Z";
    expect(validateCapsuleDict(d).ok).toBe(true);
  });

  it("strictUnknownKeys accepts a capsule with only known keys", () => {
    expect(validateCapsuleDict(minimal(), { strictUnknownKeys: true }).ok).toBe(true);
  });

  it("rejects a malformed claimedHash", () => {
    const r = validateCapsuleDict(minimal(), { claimedHash: "zz" });
    expect(r.category).toBe("invalid_value");
    expect(r.field).toBe("hash");
  });

  it("accepts an uppercase claimedHash that matches", () => {
    const d = minimal();
    const r = validateCapsuleDict(d, { claimedHash: computeHashFromDict(d).toUpperCase() });
    expect(r.ok).toBe(true);
  });
});
