use crate::capability::CapabilityType;
use chrono::{DateTime, Duration, Utc};
use security_control_plane_common::{SecurityEvent, Severity};
use security_control_plane_engine::SecuritySignal;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackStage {
    Reconnaissance = 1,
    LateralMovement = 2,
    HighImpactAction = 3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageObservation {
    pub stage: AttackStage,
    pub app_id: String,
    pub capability: Option<String>,
    pub summary: String,
    pub timestamp: DateTime<Utc>,
    pub event_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityAttackProgress {
    pub canonical_id: String,
    pub stages: Vec<StageObservation>,
    pub apps_involved: HashSet<String>,
    pub highest_stage: AttackStage,
    pub last_updated: DateTime<Utc>,
    pub alert_fired: bool,
}

pub struct CrossAppSequenceDetector {
    entity_progress: HashMap<String, EntityAttackProgress>,
    window_seconds: i64,
}

impl Default for CrossAppSequenceDetector {
    fn default() -> Self {
        Self::new(600) // 10 minutes attack correlation window
    }
}

impl CrossAppSequenceDetector {
    pub fn new(window_seconds: i64) -> Self {
        Self {
            entity_progress: HashMap::new(),
            window_seconds,
        }
    }

    /// Evaluate whether a security event indicates progression in an attack sequence
    pub fn evaluate_event(
        &mut self,
        event: &SecurityEvent,
        canonical_id: &str,
        capabilities: &[CapabilityType],
    ) -> Option<SecuritySignal> {
        let now = event.timestamp;
        let window_cutoff = now - Duration::seconds(self.window_seconds);

        // Get or initialize entity tracking
        let progress = self.entity_progress.entry(canonical_id.to_string()).or_insert_with(|| {
            EntityAttackProgress {
                canonical_id: canonical_id.to_string(),
                stages: Vec::new(),
                apps_involved: HashSet::new(),
                highest_stage: AttackStage::Reconnaissance,
                last_updated: now,
                alert_fired: false,
            }
        });

        // Prune observations outside current window
        progress.stages.retain(|obs| obs.timestamp >= window_cutoff);
        progress.apps_involved = progress.stages.iter().map(|s| s.app_id.clone()).collect();
        progress.last_updated = now;

        // Determine if this event constitutes a stage
        let is_failed = !event.action.as_ref().map(|a| a.is_success).unwrap_or(true);
        let status = event.action.as_ref().and_then(|a| a.status_code).unwrap_or(200);

        let observed_stage = if is_failed || status == 401 || status == 403 || status == 404 {
            Some((
                AttackStage::Reconnaissance,
                format!("Failed request or enumeration probe on app '{}' (HTTP {})", event.app_id, status),
            ))
        } else if capabilities.contains(&CapabilityType::AdminOperation)
            || capabilities.contains(&CapabilityType::DataExport)
            || capabilities.contains(&CapabilityType::ProcessExecute)
        {
            let cap_name = if capabilities.contains(&CapabilityType::ProcessExecute) {
                "process.execute"
            } else if capabilities.contains(&CapabilityType::DataExport) {
                "data.export"
            } else {
                "admin.operation"
            };
            Some((
                AttackStage::HighImpactAction,
                format!("High-impact capability '{}' executed on app '{}'", cap_name, event.app_id),
            ))
        } else if event.action.as_ref().map(|a| a.is_success).unwrap_or(false)
            && !progress.apps_involved.is_empty()
            && !progress.apps_involved.contains(&event.app_id)
        {
            // Successful action on a new application after prior activity
            Some((
                AttackStage::LateralMovement,
                format!("Lateral transition to application '{}' with active identity", event.app_id),
            ))
        } else {
            None
        };

        if let Some((stage, summary)) = observed_stage {
            let cap_str = capabilities.first().map(|c| c.as_str().to_string());
            progress.stages.push(StageObservation {
                stage,
                app_id: event.app_id.clone(),
                capability: cap_str,
                summary,
                timestamp: now,
                event_id: event.event_id,
            });
            progress.apps_involved.insert(event.app_id.clone());
            if stage > progress.highest_stage {
                progress.highest_stage = stage;
            }

            // Check if attack chain condition is met:
            // 1. Reached Stage 3 (HighImpactAction)
            // 2. Traversed at least 2 distinct applications
            // 3. Has at least 3 chronological stage observations
            // 4. Has not already fired an alert for this progression
            if progress.highest_stage == AttackStage::HighImpactAction
                && progress.apps_involved.len() >= 2
                && progress.stages.len() >= 3
                && !progress.alert_fired
            {
                progress.alert_fired = true;

                let app_list = progress
                    .apps_involved
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" -> ");

                let mut timeline_desc = Vec::new();
                for obs in &progress.stages {
                    timeline_desc.push(format!("[{}] {}", obs.app_id, obs.summary));
                }

                let signal = SecuritySignal {
                    signal_id: Uuid::new_v4(),
                    rule_name: "Multi-Stage Cross-Application Attack Chain".to_string(),
                    severity: Severity::Critical,
                    description: format!(
                        "Entity '{}' executed a coordinated multi-stage attack across [{}] in {}s. Attack Timeline:\n- {}",
                        canonical_id,
                        app_list,
                        self.window_seconds,
                        timeline_desc.join("\n- ")
                    ),
                    risk_weight: 75,
                    timestamp: Utc::now(),
                    matched_event_ids: progress.stages.iter().map(|s| s.event_id).collect(),
                };

                return Some(signal);
            }
        }

        None
    }

    pub fn get_progress(&self, canonical_id: &str) -> Option<&EntityAttackProgress> {
        self.entity_progress.get(canonical_id)
    }

    pub fn prune_stale(&mut self) -> usize {
        let cutoff = Utc::now() - Duration::seconds(self.window_seconds);
        let initial_len = self.entity_progress.len();
        self.entity_progress.retain(|_, p| p.last_updated >= cutoff);
        initial_len - self.entity_progress.len()
    }
}
