/**
 * Capsule data model tests.
 *
 * Tests factory functions, toDict, isSealed, and type consistency.
 */

import { describe, expect, it } from "vitest";
import {
  createCapsule,
  createTrigger,
  createContext,
  createReasoning,
  createAuthority,
  createExecution,
  createOutcome,
  toDict,
  isSealed,
} from "../src/capsule.js";

describe("createCapsule", () => {
  it("creates a capsule with all 6 sections", () => {
    const c = createCapsule();
    expect(c.trigger).toBeDefined();
    expect(c.context).toBeDefined();
    expect(c.reasoning).toBeDefined();
    expect(c.authority).toBeDefined();
    expect(c.execution).toBeDefined();
    expect(c.outcome).toBeDefined();
  });

  it("generates a UUID id", () => {
    const c = createCapsule();
    expect(c.id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
  });

  it("defaults to type agent", () => {
    expect(createCapsule().type).toBe("agent");
  });

  it("defaults sequence to 0", () => {
    expect(createCapsule().sequence).toBe(0);
  });

  it("defaults previous_hash to null", () => {
    expect(createCapsule().previous_hash).toBeNull();
  });

  it("accepts partial overrides", () => {
    const c = createCapsule({
      type: "kill",
      domain: "security",
      trigger: { source: "anomaly-detector" } as never,
    });
    expect(c.type).toBe("kill");
    expect(c.domain).toBe("security");
  });

  it("starts unsealed", () => {
    const c = createCapsule();
    expect(c.hash).toBe("");
    expect(c.signature).toBe("");
    expect(isSealed(c)).toBe(false);
  });
});

describe("toDict", () => {
  it("excludes seal fields", () => {
    const c = createCapsule();
    c.hash = "abc123";
    c.signature = "sig456";
    c.signed_at = "2026-01-01T00:00:00+00:00";
    c.signed_by = "key789";

    const dict = toDict(c);
    expect("hash" in dict).toBe(false);
    expect("signature" in dict).toBe(false);
    expect("signed_at" in dict).toBe(false);
    expect("signed_by" in dict).toBe(false);
  });

  it("includes all 13 content fields", () => {
    const dict = toDict(createCapsule());
    const keys = Object.keys(dict);
    expect(keys).toContain("id");
    expect(keys).toContain("type");
    expect(keys).toContain("domain");
    expect(keys).toContain("parent_id");
    expect(keys).toContain("sequence");
    expect(keys).toContain("previous_hash");
    expect(keys).toContain("spec_version");
    expect(keys).toContain("trigger");
    expect(keys).toContain("context");
    expect(keys).toContain("reasoning");
    expect(keys).toContain("authority");
    expect(keys).toContain("execution");
    expect(keys).toContain("outcome");
    expect(keys).toHaveLength(13);
  });
});

describe("Section Factories", () => {
  it("createTrigger sets defaults", () => {
    const t = createTrigger();
    expect(t.type).toBe("user_request");
    expect(t.source).toBe("");
    expect(t.correlation_id).toBeNull();
    expect(t.user_id).toBeNull();
    expect(t.timestamp).toContain("+00:00");
  });

  it("createContext sets defaults", () => {
    const c = createContext();
    expect(c.agent_id).toBe("");
    expect(c.session_id).toBeNull();
    expect(c.environment).toEqual({});
  });

  it("createReasoning sets confidence to 0.0", () => {
    const r = createReasoning();
    expect(r.confidence).toBe(0.0);
    expect(r.options).toEqual([]);
    expect(r.model).toBeNull();
  });

  it("createAuthority defaults to autonomous", () => {
    const a = createAuthority();
    expect(a.type).toBe("autonomous");
    expect(a.approver).toBeNull();
    expect(a.chain).toEqual([]);
  });

  it("createExecution defaults to 0 duration", () => {
    const e = createExecution();
    expect(e.tool_calls).toEqual([]);
    expect(e.duration_ms).toBe(0);
  });

  it("createOutcome defaults to pending", () => {
    const o = createOutcome();
    expect(o.status).toBe("pending");
    expect(o.result).toBeNull();
    expect(o.error).toBeNull();
    expect(o.side_effects).toEqual([]);
  });
});
