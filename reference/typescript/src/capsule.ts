/**
 * Capsule: The atomic record.
 *
 * ∀ action: ∃ capsule
 *
 * Six sections, one truth. Every action creates a Capsule.
 *
 * @license Apache-2.0
 * @see ../../spec/README.md
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type CapsuleType =
  | "agent"
  | "tool"
  | "system"
  | "kill"
  | "workflow"
  | "chat"
  | "vault"
  | "auth";

export type TriggerType = "user_request" | "scheduled" | "system" | "agent";
export type AuthorityType = "autonomous" | "human_approved" | "policy" | "escalated";
export type OutcomeStatus = "pending" | "success" | "failure" | "partial" | "blocked";

// ---------------------------------------------------------------------------
// Section 1: Trigger
// ---------------------------------------------------------------------------

export interface TriggerSection {
  type: TriggerType | string;
  source: string;
  timestamp: string;
  request: string;
  correlation_id: string | null;
  user_id: string | null;
}

// ---------------------------------------------------------------------------
// Section 2: Context
// ---------------------------------------------------------------------------

export interface ContextSection {
  agent_id: string;
  session_id: string | null;
  environment: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Section 3: Reasoning
// ---------------------------------------------------------------------------

export interface ReasoningOption {
  id: string;
  description: string;
  pros: string[];
  cons: string[];
  estimated_impact: Record<string, unknown>;
  feasibility: number;
  risks: string[];
  selected: boolean;
  rejection_reason: string;
}

export interface ReasoningSection {
  analysis: string;
  options: ReasoningOption[];
  options_considered: string[];
  selected_option: string;
  reasoning: string;
  confidence: number;
  model: string | null;
  prompt_hash: string | null;
}

// ---------------------------------------------------------------------------
// Section 4: Authority
// ---------------------------------------------------------------------------

export interface AuthoritySection {
  type: AuthorityType | string;
  approver: string | null;
  policy_reference: string | null;
  chain: Record<string, unknown>[];
  escalation_reason: string | null;
}

// ---------------------------------------------------------------------------
// Section 5: Execution
// ---------------------------------------------------------------------------

export interface ToolCall {
  tool: string;
  arguments: Record<string, unknown>;
  result: unknown;
  success: boolean;
  duration_ms: number;
  error: string | null;
}

export interface ExecutionSection {
  tool_calls: ToolCall[];
  duration_ms: number;
  resources_used: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Section 6: Outcome
// ---------------------------------------------------------------------------

export interface OutcomeSection {
  status: OutcomeStatus | string;
  result: unknown;
  summary: string;
  error: string | null;
  side_effects: string[];
  metrics: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// The Capsule
// ---------------------------------------------------------------------------

export interface CapsuleDict {
  id: string;
  type: string;
  domain: string;
  parent_id: string | null;
  sequence: number;
  previous_hash: string | null;
  /** CPS wire-format version (included in canonical hash). */
  spec_version: string;
  trigger: TriggerSection;
  context: ContextSection;
  reasoning: ReasoningSection;
  authority: AuthoritySection;
  execution: ExecutionSection;
  outcome: OutcomeSection;
}

export interface SealFields {
  hash: string;
  signature: string;
  signature_pq: string;
  signed_at: string | null;
  signed_by: string;
}

export interface Capsule extends CapsuleDict, SealFields {}

// ---------------------------------------------------------------------------
// Factories
// ---------------------------------------------------------------------------

export function createTrigger(partial?: Partial<TriggerSection>): TriggerSection {
  return {
    type: "user_request",
    source: "",
    timestamp: new Date().toISOString().replace("Z", "+00:00"),
    request: "",
    correlation_id: null,
    user_id: null,
    ...partial,
  };
}

export function createContext(partial?: Partial<ContextSection>): ContextSection {
  return {
    agent_id: "",
    session_id: null,
    environment: {},
    ...partial,
  };
}

export function createReasoning(partial?: Partial<ReasoningSection>): ReasoningSection {
  return {
    analysis: "",
    options: [],
    options_considered: [],
    selected_option: "",
    reasoning: "",
    confidence: 0.0,
    model: null,
    prompt_hash: null,
    ...partial,
  };
}

export function createAuthority(partial?: Partial<AuthoritySection>): AuthoritySection {
  return {
    type: "autonomous",
    approver: null,
    policy_reference: null,
    chain: [],
    escalation_reason: null,
    ...partial,
  };
}

export function createExecution(partial?: Partial<ExecutionSection>): ExecutionSection {
  return {
    tool_calls: [],
    duration_ms: 0,
    resources_used: {},
    ...partial,
  };
}

export function createOutcome(partial?: Partial<OutcomeSection>): OutcomeSection {
  return {
    status: "pending",
    result: null,
    summary: "",
    error: null,
    side_effects: [],
    metrics: {},
    ...partial,
  };
}

export function createCapsule(
  partial?: Partial<CapsuleDict> & { type?: CapsuleType },
): Capsule {
  const {
    trigger, context, reasoning, authority, execution, outcome,
    ...scalars
  } = partial ?? {};

  return {
    id: crypto.randomUUID(),
    type: "agent",
    domain: "agents",
    parent_id: null,
    sequence: 0,
    previous_hash: null,
    spec_version: "1.0",
    ...scalars,
    trigger: createTrigger(trigger),
    context: createContext(context),
    reasoning: createReasoning(reasoning),
    authority: createAuthority(authority),
    execution: createExecution(execution),
    outcome: createOutcome(outcome),
    hash: "",
    signature: "",
    signature_pq: "",
    signed_at: null,
    signed_by: "",
  };
}

/**
 * Extract the content dict from a Capsule (excludes seal fields).
 * This is the equivalent of Python's `capsule.to_dict()`.
 */
export function toDict(capsule: Capsule): CapsuleDict {
  return {
    id: capsule.id,
    type: capsule.type,
    domain: capsule.domain,
    parent_id: capsule.parent_id,
    sequence: capsule.sequence,
    previous_hash: capsule.previous_hash,
    spec_version: capsule.spec_version,
    trigger: capsule.trigger,
    context: capsule.context,
    reasoning: capsule.reasoning,
    authority: capsule.authority,
    execution: capsule.execution,
    outcome: capsule.outcome,
  };
}

export function isSealed(capsule: Capsule): boolean {
  return !!(capsule.hash && capsule.signature);
}
