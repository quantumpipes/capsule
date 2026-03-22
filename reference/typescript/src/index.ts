/**
 * @quantumpipes/capsule
 *
 * Capsule Protocol Specification (CPS) — TypeScript reference implementation.
 * Tamper-evident audit records for AI operations.
 *
 * @license Apache-2.0
 * @see ../../spec/README.md
 */

export {
  type Capsule,
  type CapsuleDict,
  type CapsuleType,
  type TriggerSection,
  type ContextSection,
  type ReasoningSection,
  type ReasoningOption,
  type AuthoritySection,
  type ExecutionSection,
  type ToolCall,
  type OutcomeSection,
  type SealFields,
  createCapsule,
  createTrigger,
  createContext,
  createReasoning,
  createAuthority,
  createExecution,
  createOutcome,
  toDict,
  isSealed,
} from "./capsule.js";

export { canonicalize } from "./canonical.js";

export {
  computeHash,
  computeHashFromDict,
  seal,
  verify,
  verifyDetailed,
  type SealVerificationResult,
  type SealVerifyCode,
  generateKeyPair,
  getFingerprint,
} from "./seal.js";

export {
  type ChainVerificationResult,
  verifyChain,
} from "./chain.js";

export {
  type CapsuleValidationResult,
  type ValidateCapsuleDictOptions,
  validateCapsuleDict,
} from "./validation.js";
