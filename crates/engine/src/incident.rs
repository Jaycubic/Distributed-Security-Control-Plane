use chrono::{DateTime, Utc};
use security_control_plane_common::{SecurityEvent, Severity};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    Open,
    Investigating,
    Contained,
    Resolved,
    FalsePositive,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecuritySignal {
    pub signal_id: Uuid,
    pub rule_name: String,
    pub severity: Severity,
    pub description: String,
    pub risk_weight: u32,
    pub timestamp: DateTime<Utc>,
    pub matched_event_ids: Vec<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Incident {
    pub incident_id: Uuid,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub status: IncidentStatus,
    pub target_entity: String,
    pub app_id: String,
    pub risk_score: u32,
    pub signals: Vec<SecuritySignal>,
    pub evidence: Vec<SecurityEvent>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Incident {
    pub fn new(
        title: impl Into<String>,
        description: impl Into<String>,
        severity: Severity,
        target_entity: impl Into<String>,
        app_id: impl Into<String>,
        initial_signal: SecuritySignal,
        initial_event: SecurityEvent,
    ) -> Self {
        let now = Utc::now();
        let risk_score = initial_signal.risk_weight;
        Self {
            incident_id: Uuid::new_v4(),
            title: title.into(),
            description: description.into(),
            severity,
            status: IncidentStatus::Open,
            target_entity: target_entity.into(),
            app_id: app_id.into(),
            risk_score,
            signals: vec![initial_signal],
            evidence: vec![initial_event],
            created_at: now,
            updated_at: now,
        }
    }

    pub fn add_signal(&mut self, signal: SecuritySignal, event: Option<SecurityEvent>) {
        self.risk_score = self.risk_score.saturating_add(signal.risk_weight);
        self.signals.push(signal);
        if let Some(ev) = event {
            // Keep recent evidence bounded to last 50 events
            if self.evidence.len() >= 50 {
                self.evidence.remove(0);
            }
            self.evidence.push(ev);
        }
        self.updated_at = Utc::now();

        // Dynamically escalate severity based on accumulated risk score
        if self.risk_score >= 100 {
            self.severity = Severity::Critical;
        } else if self.risk_score >= 50 {
            self.severity = Severity::High;
        } else if self.risk_score >= 25 {
            self.severity = Severity::Medium;
        }
    }
}
