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
        let signal_severity = signal.severity.clone();
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
        let score_severity = if self.risk_score >= 100 {
            Severity::Critical
        } else if self.risk_score >= 50 {
            Severity::High
        } else if self.risk_score >= 25 {
            Severity::Medium
        } else {
            Severity::Low
        };
        self.severity = self
            .severity
            .clone()
            .max(signal_severity)
            .max(score_severity);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use security_control_plane_common::{SensorMetadata, SensorType, SourceContext};

    #[test]
    fn adding_a_lower_risk_signal_does_not_downgrade_critical_incident() {
        let event = SecurityEvent::new(
            "test-app",
            "test",
            "test.event",
            SourceContext {
                ip: None,
                port: None,
                user_agent: None,
                sensor: SensorMetadata {
                    sensor_type: SensorType::Agent,
                    raw_event_type: "test.event".into(),
                    sensor_id: None,
                    raw_payload: None,
                },
                container_id: None,
                pid: None,
                process_name: None,
            },
        );
        let critical_signal = SecuritySignal {
            signal_id: Uuid::new_v4(),
            rule_name: "critical rule".into(),
            severity: Severity::Critical,
            description: "critical signal".into(),
            risk_weight: 50,
            timestamp: Utc::now(),
            matched_event_ids: vec![event.event_id],
        };
        let mut incident = Incident::new(
            "critical incident",
            "critical signal",
            Severity::Critical,
            "test-entity",
            "test-app",
            critical_signal,
            event.clone(),
        );
        let lower_risk_signal = SecuritySignal {
            signal_id: Uuid::new_v4(),
            rule_name: "lower risk rule".into(),
            severity: Severity::Medium,
            description: "lower risk signal".into(),
            risk_weight: 40,
            timestamp: Utc::now(),
            matched_event_ids: vec![event.event_id],
        };

        incident.add_signal(lower_risk_signal, Some(event));

        assert_eq!(incident.severity, Severity::Critical);
    }
}
