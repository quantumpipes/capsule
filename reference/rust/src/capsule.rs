//! Capsule: The atomic record.
//!
//! ∀ action: ∃ capsule
//!
//! Six sections, one truth. Every action creates a Capsule.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

/// Types of recorded actions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CapsuleType {
    Agent,
    Tool,
    System,
    Kill,
    Workflow,
    Chat,
    Vault,
    Auth,
}

impl std::fmt::Display for CapsuleType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Agent => "agent",
            Self::Tool => "tool",
            Self::System => "system",
            Self::Kill => "kill",
            Self::Workflow => "workflow",
            Self::Chat => "chat",
            Self::Vault => "vault",
            Self::Auth => "auth",
        };
        write!(f, "{}", s)
    }
}

/// Section 1: What initiated this action?
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerSection {
    #[serde(rename = "type")]
    pub trigger_type: String,
    pub source: String,
    pub timestamp: String,
    pub request: String,
    pub correlation_id: Option<String>,
    pub user_id: Option<String>,
}

impl Default for TriggerSection {
    fn default() -> Self {
        Self {
            trigger_type: "user_request".into(),
            source: String::new(),
            timestamp: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S+00:00").to_string(),
            request: String::new(),
            correlation_id: None,
            user_id: None,
        }
    }
}

/// Section 2: What was the state of the world?
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContextSection {
    pub agent_id: String,
    pub session_id: Option<String>,
    pub environment: BTreeMap<String, serde_json::Value>,
}

/// A single option considered during AI deliberation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningOption {
    pub id: String,
    pub description: String,
    pub pros: Vec<String>,
    pub cons: Vec<String>,
    pub estimated_impact: BTreeMap<String, serde_json::Value>,
    pub feasibility: f64,
    pub risks: Vec<String>,
    pub selected: bool,
    pub rejection_reason: String,
}

/// Section 3: Why was this decision made?
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReasoningSection {
    pub analysis: String,
    pub options: Vec<ReasoningOption>,
    pub options_considered: Vec<String>,
    pub selected_option: String,
    pub reasoning: String,
    pub confidence: f64,
    pub model: Option<String>,
    pub prompt_hash: Option<String>,
}

/// Section 4: Who/what approved this action?
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthoritySection {
    #[serde(rename = "type")]
    pub authority_type: String,
    pub approver: Option<String>,
    pub policy_reference: Option<String>,
    pub chain: Vec<BTreeMap<String, serde_json::Value>>,
    pub escalation_reason: Option<String>,
}

impl Default for AuthoritySection {
    fn default() -> Self {
        Self {
            authority_type: "autonomous".into(),
            approver: None,
            policy_reference: None,
            chain: Vec::new(),
            escalation_reason: None,
        }
    }
}

/// A single tool invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub tool: String,
    pub arguments: BTreeMap<String, serde_json::Value>,
    pub result: serde_json::Value,
    pub success: bool,
    pub duration_ms: i64,
    pub error: Option<String>,
}

/// Section 5: What actually happened?
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExecutionSection {
    pub tool_calls: Vec<ToolCall>,
    pub duration_ms: i64,
    pub resources_used: BTreeMap<String, serde_json::Value>,
}

/// Section 6: What was the result?
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutcomeSection {
    pub status: String,
    pub result: serde_json::Value,
    pub summary: String,
    pub error: Option<String>,
    pub side_effects: Vec<String>,
    pub metrics: BTreeMap<String, serde_json::Value>,
}

impl Default for OutcomeSection {
    fn default() -> Self {
        Self {
            status: "pending".into(),
            result: serde_json::Value::Null,
            summary: String::new(),
            error: None,
            side_effects: Vec::new(),
            metrics: BTreeMap::new(),
        }
    }
}

/// The CPS version this SDK writes.
pub const SPEC_VERSION: &str = "1.0";

fn default_spec_version() -> String {
    SPEC_VERSION.to_string()
}

/// The atomic record: a complete, sealed record of a single action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capsule {
    pub id: String,
    #[serde(rename = "type")]
    pub capsule_type: CapsuleType,
    pub domain: String,
    pub parent_id: Option<String>,
    pub sequence: i64,
    pub previous_hash: Option<String>,
    /// CPS version this Capsule conforms to. Part of the hashed content (CPS 1.0).
    #[serde(default = "default_spec_version")]
    pub spec_version: String,

    pub trigger: TriggerSection,
    pub context: ContextSection,
    pub reasoning: ReasoningSection,
    pub authority: AuthoritySection,
    pub execution: ExecutionSection,
    pub outcome: OutcomeSection,

    // Seal fields (not part of canonical content)
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub hash: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub signature: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub signature_pq: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub signed_at: Option<String>,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub signed_by: String,
}

impl Capsule {
    /// Create a new Capsule with sensible defaults.
    pub fn new(capsule_type: CapsuleType) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            capsule_type,
            domain: "agents".into(),
            parent_id: None,
            sequence: 0,
            previous_hash: None,
            spec_version: default_spec_version(),
            trigger: TriggerSection::default(),
            context: ContextSection::default(),
            reasoning: ReasoningSection::default(),
            authority: AuthoritySection::default(),
            execution: ExecutionSection::default(),
            outcome: OutcomeSection::default(),
            hash: String::new(),
            signature: String::new(),
            signature_pq: String::new(),
            signed_at: None,
            signed_by: String::new(),
        }
    }

    /// Check if the Capsule has been sealed.
    pub fn is_sealed(&self) -> bool {
        !self.hash.is_empty() && !self.signature.is_empty()
    }

    /// Convert to content dict (serde_json::Value) excluding seal fields.
    pub fn to_dict(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "type": self.capsule_type,
            "domain": self.domain,
            "parent_id": self.parent_id,
            "sequence": self.sequence,
            "previous_hash": self.previous_hash,
            "spec_version": self.spec_version,
            "trigger": {
                "type": self.trigger.trigger_type,
                "source": self.trigger.source,
                "timestamp": self.trigger.timestamp,
                "request": self.trigger.request,
                "correlation_id": self.trigger.correlation_id,
                "user_id": self.trigger.user_id,
            },
            "context": {
                "agent_id": self.context.agent_id,
                "session_id": self.context.session_id,
                "environment": self.context.environment,
            },
            "reasoning": {
                "analysis": self.reasoning.analysis,
                "options": self.reasoning.options.iter().map(|o| serde_json::json!({
                    "id": o.id,
                    "description": o.description,
                    "pros": o.pros,
                    "cons": o.cons,
                    "estimated_impact": o.estimated_impact,
                    "feasibility": o.feasibility,
                    "risks": o.risks,
                    "selected": o.selected,
                    "rejection_reason": o.rejection_reason,
                })).collect::<Vec<_>>(),
                "options_considered": self.reasoning.options_considered,
                "selected_option": self.reasoning.selected_option,
                "reasoning": self.reasoning.reasoning,
                "confidence": self.reasoning.confidence,
                "model": self.reasoning.model,
                "prompt_hash": self.reasoning.prompt_hash,
            },
            "authority": {
                "type": self.authority.authority_type,
                "approver": self.authority.approver,
                "policy_reference": self.authority.policy_reference,
                "chain": self.authority.chain,
                "escalation_reason": self.authority.escalation_reason,
            },
            "execution": {
                "tool_calls": self.execution.tool_calls.iter().map(|tc| serde_json::json!({
                    "tool": tc.tool,
                    "arguments": tc.arguments,
                    "result": tc.result,
                    "success": tc.success,
                    "duration_ms": tc.duration_ms,
                    "error": tc.error,
                })).collect::<Vec<_>>(),
                "duration_ms": self.execution.duration_ms,
                "resources_used": self.execution.resources_used,
            },
            "outcome": {
                "status": self.outcome.status,
                "result": self.outcome.result,
                "summary": self.outcome.summary,
                "error": self.outcome.error,
                "side_effects": self.outcome.side_effects,
                "metrics": self.outcome.metrics,
            },
        })
    }
}

impl std::fmt::Display for Capsule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Capsule({}, type={}, status={}, sealed={})",
            self.id,
            self.capsule_type,
            self.outcome.status,
            self.is_sealed()
        )
    }
}
