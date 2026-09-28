pub mod gate;

pub use gate::AdvisoryPolicyGate;

use crate::containment::ContainmentManager;
use crate::incident::Incident;
use crate::policy::CapabilityPolicyEngine;
use chrono::Utc;
use security_control_plane_common::{
    AdvisoryRecommendation, AdvisoryValidationResult, AmbiguousIncidentContext, ControlPlaneMode,
    EvidenceSummary, SecuritySignalSummary,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

/// Controller for Dual Mode Execution (Mode A: Deterministic, Mode B: Advisory AI).
/// Manages active execution mode, stores advisory recommendation audit logs,
/// and delegates recommendation authorization to the deterministic policy gate.
pub struct AdvisoryManager {
    mode: RwLock<ControlPlaneMode>,
    gate: Arc<AdvisoryPolicyGate>,
    history: RwLock<Vec<(AdvisoryRecommendation, AdvisoryValidationResult)>>,
    worker_url: RwLock<String>,
}

impl AdvisoryManager {
    pub fn new(
        gate: Arc<AdvisoryPolicyGate>,
        initial_mode: ControlPlaneMode,
        worker_url: impl Into<String>,
    ) -> Self {
        Self {
            mode: RwLock::new(initial_mode),
            gate,
            history: RwLock::new(Vec::new()),
            worker_url: RwLock::new(worker_url.into()),
        }
    }

    pub fn with_defaults(
        policy_engine: Arc<CapabilityPolicyEngine>,
        containment_mgr: Arc<ContainmentManager>,
    ) -> Self {
        let gate = Arc::new(AdvisoryPolicyGate::with_defaults(
            policy_engine,
            containment_mgr,
        ));
        let default_worker_url = std::env::var("LLM_WORKER_URL")
            .unwrap_or_else(|_| "http://localhost:8000".to_string());

        let initial_mode = match std::env::var("CONTROL_PLANE_MODE") {
            Ok(val) if val.eq_ignore_ascii_case("modeb") || val.eq_ignore_ascii_case("mode_b") => {
                ControlPlaneMode::ModeB
            }
            _ => ControlPlaneMode::ModeA, // Mode A baseline by default!
        };

        Self::new(gate, initial_mode, default_worker_url)
    }

    /// Returns current control plane execution mode.
    pub async fn get_mode(&self) -> ControlPlaneMode {
        *self.mode.read().await
    }

    /// Sets control plane execution mode (Mode A or Mode B).
    pub async fn set_mode(&self, new_mode: ControlPlaneMode) {
        let mut lock = self.mode.write().await;
        if *lock != new_mode {
            info!(
                previous = lock.as_str(),
                new = new_mode.as_str(),
                "Switched Control Plane execution mode"
            );
            *lock = new_mode;
        }
    }

    /// Returns whether Mode B is active.
    pub async fn is_mode_b(&self) -> bool {
        *self.mode.read().await == ControlPlaneMode::ModeB
    }

    /// Returns the configured Python advisory worker URL.
    pub async fn get_worker_url(&self) -> String {
        self.worker_url.read().await.clone()
    }

    /// Updates the configured Python advisory worker URL.
    pub async fn set_worker_url(&self, url: impl Into<String>) {
        let mut lock = self.worker_url.write().await;
        *lock = url.into();
    }

    /// Evaluates an advisory recommendation against the deterministic policy gate
    /// and records the recommendation and validation outcome in history.
    pub async fn validate_and_enact(
        &self,
        rec: AdvisoryRecommendation,
    ) -> AdvisoryValidationResult {
        let result = self.gate.validate_and_enact(&rec).await;
        let mut hist = self.history.write().await;
        hist.push((rec, result.clone()));
        result
    }

    /// Returns all historical advisory recommendations and their gate outcomes.
    pub async fn get_history(&self) -> Vec<(AdvisoryRecommendation, AdvisoryValidationResult)> {
        self.history.read().await.clone()
    }

    /// Builds a structured, redacted context payload from an Incident
    /// suitable for consumption by the off-path reasoning worker.
    pub fn build_incident_context(
        incident: &Incident,
        applicable_policies: Vec<String>,
    ) -> AmbiguousIncidentContext {
        let signals = incident
            .signals
            .iter()
            .map(|s| SecuritySignalSummary {
                rule_name: s.rule_name.clone(),
                severity: s.severity.clone(),
                description: s.description.clone(),
                risk_weight: s.risk_weight,
            })
            .collect();

        let evidence = incident
            .evidence
            .iter()
            .take(20) // bounded to recent 20 events
            .map(|e| EvidenceSummary {
                event_id: e.event_id,
                event_type: e.event_type.clone(),
                endpoint: e.action.as_ref().and_then(|a| a.endpoint.clone()),
                method: e.action.as_ref().and_then(|a| a.method.clone()),
                status_code: e.action.as_ref().and_then(|a| a.status_code),
                source_ip: e.source.ip.clone(),
                container_id: e.source.container_id.clone(),
                pid: e.source.pid,
                process_name: e.source.process_name.clone(),
            })
            .collect();

        AmbiguousIncidentContext {
            incident_id: incident.incident_id,
            title: incident.title.clone(),
            description: incident.description.clone(),
            target_entity: incident.target_entity.clone(),
            app_id: incident.app_id.clone(),
            risk_score: incident.risk_score,
            severity: incident.severity.clone(),
            signals,
            evidence,
            applicable_policies,
            timestamp: Utc::now(),
        }
    }
}
