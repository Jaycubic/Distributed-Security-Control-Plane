use crate::containment::ContainmentActionType;
use crate::models::Severity;
use crate::policy::DecisionOutcome;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Operational execution mode for the Security Control Plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlPlaneMode {
    /// Mode A: Purely deterministic execution. LLM is completely disabled.
    /// Default baseline security mode.
    ModeA,
    /// Mode B: Intelligent advisory execution. LLM provides asynchronous
    /// off-path reasoning for ambiguous or high-entropy incidents.
    ModeB,
}

impl Default for ControlPlaneMode {
    fn default() -> Self {
        Self::ModeA
    }
}

impl ControlPlaneMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ModeA => "Mode A (Deterministic)",
            Self::ModeB => "Mode B (Intelligent / Advisory)",
        }
    }
}

/// Threat classification determined by the advisory reasoning layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ThreatClassification {
    Benign,
    Suspicious,
    Malicious,
    Uncertain,
}

/// Structured security signal summary passed within the ambiguous incident context.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecuritySignalSummary {
    pub rule_name: String,
    pub severity: Severity,
    pub description: String,
    pub risk_weight: u32,
}

/// Structured evidence summary passed within the ambiguous incident context.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct EvidenceSummary {
    pub event_id: Uuid,
    pub event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
}

/// Structured context sent to the off-path advisory reasoning worker.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AmbiguousIncidentContext {
    pub incident_id: Uuid,
    pub title: String,
    pub description: String,
    pub target_entity: String,
    pub app_id: String,
    pub risk_score: u32,
    pub severity: Severity,
    pub signals: Vec<SecuritySignalSummary>,
    pub evidence: Vec<EvidenceSummary>,
    pub applicable_policies: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

/// Structured machine-readable recommendation returned by the advisory reasoning layer.
/// Zero direct execution privileges — must pass deterministic policy validation gate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AdvisoryRecommendation {
    pub recommendation_id: Uuid,
    pub incident_id: Uuid,
    pub target_entity: String,
    pub app_id: String,
    pub classification: ThreatClassification,
    /// Confidence score between 0.0 and 1.0
    pub confidence: f64,
    /// Standardized reason codes (e.g., ["UNUSUAL_PROCESS", "LATERAL_MOVEMENT"])
    pub reason_codes: Vec<String>,
    /// Natural language explanation of the reasoning
    pub reasoning_summary: String,
    /// Recommended containment action
    pub recommended_action: ContainmentActionType,
    /// Optional capability affected (e.g., "database.read", "process.execute")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,
    /// Key-value parameters for containment enforcement
    #[serde(default)]
    pub params: HashMap<String, String>,
    /// Suggested TTL for the containment command in seconds
    pub suggested_ttl_seconds: u64,
    /// Model provider or engine that generated this recommendation
    pub model_provider: String,
    pub created_at: DateTime<Utc>,
}

impl AdvisoryRecommendation {
    pub fn new(
        incident_id: Uuid,
        target_entity: impl Into<String>,
        app_id: impl Into<String>,
        classification: ThreatClassification,
        confidence: f64,
        reason_codes: Vec<String>,
        reasoning_summary: impl Into<String>,
        recommended_action: ContainmentActionType,
        capability: Option<String>,
        params: HashMap<String, String>,
        suggested_ttl_seconds: u64,
        model_provider: impl Into<String>,
    ) -> Self {
        Self {
            recommendation_id: Uuid::new_v4(),
            incident_id,
            target_entity: target_entity.into(),
            app_id: app_id.into(),
            classification,
            confidence: confidence.clamp(0.0, 1.0),
            reason_codes,
            reasoning_summary: reasoning_summary.into(),
            recommended_action,
            capability,
            params,
            suggested_ttl_seconds,
            model_provider: model_provider.into(),
            created_at: Utc::now(),
        }
    }
}

/// Output of the Deterministic Policy Validation Gate evaluating an AdvisoryRecommendation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AdvisoryValidationResult {
    pub validation_id: Uuid,
    pub recommendation_id: Uuid,
    pub incident_id: Uuid,
    /// Whether the recommendation was approved by deterministic policy
    pub is_authorized: bool,
    /// Explicit policy decision outcome (Allow vs Deny)
    pub decision: DecisionOutcome,
    /// Policy bundle ID that authorized or rejected the recommendation
    pub policy_id: String,
    /// Detailed rationale for policy validation outcome
    pub rationale: String,
    /// If authorized, the generated Ed25519-signed containment command ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub containment_command_id: Option<Uuid>,
    pub evaluated_at: DateTime<Utc>,
}
