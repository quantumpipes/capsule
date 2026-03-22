/**
 * Runtime validation for CPS capsule content dictionaries (FR-002).
 *
 * @license Apache-2.0
 */

import { computeHashFromDict } from "./seal.js";

/** Result of {@link validateCapsuleDict}. */
export interface CapsuleValidationResult {
  ok: boolean;
  category: string | null;
  field: string | null;
  message: string;
}

const VALID_CAPSULE_TYPES = new Set([
  "agent",
  "tool",
  "system",
  "kill",
  "workflow",
  "chat",
  "vault",
  "auth",
]);

const ORDERED_TOP_LEVEL = [
  "id",
  "type",
  "domain",
  "parent_id",
  "sequence",
  "previous_hash",
  "spec_version",
  "trigger",
  "context",
  "reasoning",
  "authority",
  "execution",
  "outcome",
] as const;

const REQUIRED_TOP_LEVEL = new Set<string>(ORDERED_TOP_LEVEL);

const TRIGGER_KEYS = new Set([
  "type",
  "source",
  "timestamp",
  "request",
  "correlation_id",
  "user_id",
]);
const CONTEXT_KEYS = new Set(["agent_id", "session_id", "environment"]);
const REASONING_KEYS = new Set([
  "analysis",
  "options",
  "options_considered",
  "selected_option",
  "reasoning",
  "confidence",
  "model",
  "prompt_hash",
]);
const AUTHORITY_KEYS = new Set([
  "type",
  "approver",
  "policy_reference",
  "chain",
  "escalation_reason",
]);
const EXECUTION_KEYS = new Set(["tool_calls", "duration_ms", "resources_used"]);
const OUTCOME_KEYS = new Set([
  "status",
  "result",
  "summary",
  "error",
  "side_effects",
  "metrics",
]);

function fail(
  category: string,
  field: string,
  message: string,
): CapsuleValidationResult {
  return { ok: false, category, field, message };
}

function success(): CapsuleValidationResult {
  return { ok: true, category: null, field: null, message: "" };
}

function isUuidString(s: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s);
}

function isHex64Loose(s: string): boolean {
  return s.length === 64 && /^[0-9a-f]+$/i.test(s);
}

function hasIso8601Timezone(ts: string): boolean {
  if (ts.endsWith("Z")) return !Number.isNaN(Date.parse(ts));
  return /[+-]\d{2}:\d{2}$/.test(ts) && !Number.isNaN(Date.parse(ts));
}

export interface ValidateCapsuleDictOptions {
  /** If set, must match {@link computeHashFromDict} of *data*. */
  claimedHash?: string;
  /** Reject unknown top-level keys. */
  strictUnknownKeys?: boolean;
}

/**
 * Validate a CPS capsule **content** object (pre-seal / `toDict` shape).
 */
export function validateCapsuleDict(
  data: unknown,
  options: ValidateCapsuleDictOptions = {},
): CapsuleValidationResult {
  const { claimedHash, strictUnknownKeys = false } = options;

  if (typeof data !== "object" || data === null || Array.isArray(data)) {
    return fail("wrong_type", "", "capsule root must be a JSON object");
  }

  const d = data as Record<string, unknown>;

  if (strictUnknownKeys) {
    const extra = Object.keys(d).filter((k) => !REQUIRED_TOP_LEVEL.has(k));
    extra.sort();
    if (extra.length > 0) {
      const name = extra[0]!;
      return fail("invalid_value", name, `unknown top-level key: '${name}'`);
    }
  }

  for (const key of ORDERED_TOP_LEVEL) {
    if (!(key in d)) {
      return fail("missing_field", key, `missing required field '${key}'`);
    }
  }

  if (typeof d["id"] !== "string" || !isUuidString(d["id"])) {
    return fail(
      typeof d["id"] === "string" ? "invalid_value" : "wrong_type",
      "id",
      "id must be a UUID string",
    );
  }

  if (typeof d["type"] !== "string") {
    return fail("wrong_type", "type", "type must be a string");
  }
  if (!VALID_CAPSULE_TYPES.has(d["type"])) {
    return fail("invalid_value", "type", `unknown capsule type '${String(d["type"])}'`);
  }

  if (typeof d["domain"] !== "string") {
    return fail("wrong_type", "domain", "domain must be a string");
  }

  const pid = d["parent_id"];
  if (pid !== null) {
    if (typeof pid !== "string" || !isUuidString(pid)) {
      return fail(
        typeof pid === "string" ? "invalid_value" : "wrong_type",
        "parent_id",
        "parent_id must be null or a UUID string",
      );
    }
  }

  if (typeof d["sequence"] !== "number" || !Number.isInteger(d["sequence"])) {
    return fail("wrong_type", "sequence", "sequence must be an integer");
  }
  if ((d["sequence"] as number) < 0) {
    return fail("invalid_value", "sequence", "sequence must be non-negative");
  }

  const ph = d["previous_hash"];
  if (ph !== null) {
    if (typeof ph !== "string" || !isHex64Loose(ph)) {
      return fail(
        typeof ph === "string" ? "invalid_value" : "wrong_type",
        "previous_hash",
        "previous_hash must be null or a 64-character hex string",
      );
    }
  }

  const sv = d["spec_version"];
  if (typeof sv !== "string" || sv.length === 0) {
    return fail(
      typeof sv === "string" ? "invalid_value" : "wrong_type",
      "spec_version",
      "spec_version must be a non-empty string",
    );
  }

  const seq = d["sequence"] as number;
  if (seq === 0 && ph !== null) {
    return fail(
      "chain_violation",
      "previous_hash",
      "genesis capsule (sequence 0) must have previous_hash null",
    );
  }
  if (seq !== 0 && ph === null) {
    return fail(
      "chain_violation",
      "previous_hash",
      "non-genesis capsule must have previous_hash set",
    );
  }

  const t = d["trigger"];
  if (typeof t !== "object" || t === null || Array.isArray(t)) {
    return fail("wrong_type", "trigger", "trigger must be an object");
  }
  const tr = t as Record<string, unknown>;
  for (const k of TRIGGER_KEYS) {
    if (!(k in tr)) {
      return fail("missing_field", `trigger.${k}`, `missing required field 'trigger.${k}'`);
    }
  }
  if (tr["type"] === null || typeof tr["type"] !== "string") {
    return fail("wrong_type", "trigger.type", "trigger.type must be a non-null string");
  }
  if (
    typeof tr["timestamp"] !== "string" ||
    !hasIso8601Timezone(tr["timestamp"] as string)
  ) {
    return fail(
      typeof tr["timestamp"] === "string" ? "invalid_value" : "wrong_type",
      "trigger.timestamp",
      "trigger.timestamp must be an ISO 8601 string with timezone",
    );
  }

  const ctx = d["context"];
  if (typeof ctx !== "object" || ctx === null || Array.isArray(ctx)) {
    return fail("wrong_type", "context", "context must be an object");
  }
  const cx = ctx as Record<string, unknown>;
  for (const k of CONTEXT_KEYS) {
    if (!(k in cx)) {
      return fail("missing_field", `context.${k}`, `missing required field 'context.${k}'`);
    }
  }
  if (typeof cx["environment"] !== "object" || cx["environment"] === null || Array.isArray(cx["environment"])) {
    return fail("wrong_type", "context.environment", "context.environment must be an object");
  }

  const r = d["reasoning"];
  if (typeof r !== "object" || r === null || Array.isArray(r)) {
    return fail("wrong_type", "reasoning", "reasoning must be an object");
  }
  const rs = r as Record<string, unknown>;
  for (const k of REASONING_KEYS) {
    if (!(k in rs)) {
      return fail("missing_field", `reasoning.${k}`, `missing required field 'reasoning.${k}'`);
    }
  }
  const confRaw = rs["confidence"];
  if (typeof confRaw === "boolean" || typeof confRaw !== "number") {
    return fail("wrong_type", "reasoning.confidence", "reasoning.confidence must be a number");
  }
  const c = confRaw as number;
  if (c < 0 || c > 1) {
    return fail("invalid_value", "reasoning.confidence", "reasoning.confidence must be between 0.0 and 1.0");
  }

  const a = d["authority"];
  if (typeof a !== "object" || a === null || Array.isArray(a)) {
    return fail("wrong_type", "authority", "authority must be an object");
  }
  const au = a as Record<string, unknown>;
  for (const k of AUTHORITY_KEYS) {
    if (!(k in au)) {
      return fail("missing_field", `authority.${k}`, `missing required field 'authority.${k}'`);
    }
  }

  const e = d["execution"];
  if (typeof e !== "object" || e === null || Array.isArray(e)) {
    return fail("wrong_type", "execution", "execution must be an object");
  }
  const ex = e as Record<string, unknown>;
  for (const k of EXECUTION_KEYS) {
    if (!(k in ex)) {
      return fail("missing_field", `execution.${k}`, `missing required field 'execution.${k}'`);
    }
  }
  if (!Array.isArray(ex["tool_calls"])) {
    return fail("wrong_type", "execution.tool_calls", "execution.tool_calls must be an array");
  }
  if (typeof ex["duration_ms"] !== "number" || !Number.isInteger(ex["duration_ms"])) {
    return fail("wrong_type", "execution.duration_ms", "execution.duration_ms must be an integer");
  }
  const ru = ex["resources_used"];
  if (typeof ru !== "object" || ru === null || Array.isArray(ru)) {
    return fail("wrong_type", "execution.resources_used", "execution.resources_used must be an object");
  }

  const o = d["outcome"];
  if (typeof o !== "object" || o === null || Array.isArray(o)) {
    return fail("wrong_type", "outcome", "outcome must be an object");
  }
  const ou = o as Record<string, unknown>;
  for (const k of OUTCOME_KEYS) {
    if (!(k in ou)) {
      return fail("missing_field", `outcome.${k}`, `missing required field 'outcome.${k}'`);
    }
  }

  if (claimedHash !== undefined) {
    if (typeof claimedHash !== "string" || !isHex64Loose(claimedHash)) {
      return fail("invalid_value", "hash", "claimed_hash must be a 64-character hex string");
    }
    const computed = computeHashFromDict(d);
    const want = claimedHash.toLowerCase();
    if (computed !== want) {
      return fail("integrity_violation", "hash", "content hash does not match claimed_hash");
    }
  }

  return success();
}
