use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SensorType {
    Agent,
    Tetragon,
    Falco,
    Hubble,
    Network,
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SensorMetadata {
    pub sensor_type: SensorType,
    pub raw_event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sensor_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_payload: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct ActorContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SourceContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    pub sensor: SensorMetadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct ActionContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_us: Option<u64>,
    pub is_success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct ResourceContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sensitivity_tier: Option<String>,
}

/// The Canonical Unified Security Event Schema.
/// Preserves source-specific telemetry semantics while normalizing
/// actors, sources, actions, and resources across heterogeneous applications.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityEvent {
    pub event_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub app_id: String,
    pub environment: String,
    pub event_type: String,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<ActorContext>,
    pub source: SourceContext,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<ActionContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceContext>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, serde_json::Value>,
    /// Security significance indicator used by the selective persistence filter
    #[serde(default)]
    pub is_security_significant: bool,
}

impl SecurityEvent {
    pub fn new(
        app_id: impl Into<String>,
        environment: impl Into<String>,
        event_type: impl Into<String>,
        source: SourceContext,
    ) -> Self {
        Self {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            app_id: app_id.into(),
            environment: environment.into(),
            event_type: event_type.into(),
            severity: Severity::Low,
            actor: None,
            source,
            action: None,
            resource: None,
            metadata: HashMap::new(),
            is_security_significant: false,
        }
    }
}
