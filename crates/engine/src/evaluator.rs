use crate::incident::{Incident, IncidentStatus, SecuritySignal};
use crate::rules::{
    BruteForceRule, KernelAnomalyRule, MassDataScrapingRule, PrivilegeCreepRule,
    RapidApiEnumerationRule, Rule, UnauthorizedBurstRule,
};
use crate::state::{HotStateError, HotStateStore};
use security_control_plane_common::SecurityEvent;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tracing::{info, warn};
use uuid::Uuid;

/// Deterministic Rule Engine that correlates security events against hot state,
/// generates signals, dynamically adjusts risk, and manages incident lifecycles.
pub struct RuleEngine {
    rules: Vec<Box<dyn Rule>>,
    state: Arc<dyn HotStateStore>,
    active_incidents: Arc<RwLock<HashMap<String, Incident>>>,
    incident_history: Arc<RwLock<Vec<Incident>>>,
    incident_tx: broadcast::Sender<Incident>,
}

impl RuleEngine {
    /// Create a new RuleEngine with specified state backend and custom rules.
    pub fn new(state: Arc<dyn HotStateStore>, rules: Vec<Box<dyn Rule>>) -> Self {
        let (incident_tx, _) = broadcast::channel(1024);
        Self {
            rules,
            state,
            active_incidents: Arc::new(RwLock::new(HashMap::new())),
            incident_history: Arc::new(RwLock::new(Vec::new())),
            incident_tx,
        }
    }

    /// Instantiate RuleEngine with all default Phase 2 deterministic rules registered.
    pub fn with_default_rules(state: Arc<dyn HotStateStore>) -> Self {
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(BruteForceRule::default()),
            Box::new(RapidApiEnumerationRule::default()),
            Box::new(UnauthorizedBurstRule::default()),
            Box::new(MassDataScrapingRule::default()),
            Box::new(KernelAnomalyRule),
            Box::new(PrivilegeCreepRule),
        ];
        Self::new(state, rules)
    }

    /// Subscribe to real-time incident generation and escalation notifications.
    pub fn subscribe_incidents(&self) -> broadcast::Receiver<Incident> {
        self.incident_tx.subscribe()
    }

    /// Evaluate an incoming SecurityEvent against all registered rules.
    /// Spawns or escalates incidents when signals are triggered.
    pub async fn evaluate_event(
        &self,
        event: &SecurityEvent,
    ) -> Result<Vec<SecuritySignal>, HotStateError> {
        let mut generated_signals = Vec::new();

        for rule in &self.rules {
            if let Some(signal) = rule.evaluate(event, self.state.as_ref()).await? {
                info!(
                    rule = rule.name(),
                    event_id = %event.event_id,
                    severity = ?signal.severity,
                    "Security rule triggered signal"
                );

                self.process_signal(signal.clone(), event).await?;
                generated_signals.push(signal);
            }
        }

        Ok(generated_signals)
    }

    /// Public method to ingest a security signal from an external source (e.g. Correlation Engine)
    pub async fn ingest_signal(
        &self,
        signal: SecuritySignal,
        event: &SecurityEvent,
    ) -> Result<(), HotStateError> {
        self.process_signal(signal, event).await
    }

    async fn process_signal(
        &self,
        signal: SecuritySignal,
        event: &SecurityEvent,
    ) -> Result<(), HotStateError> {
        // Derive target entity identifier
        let target_entity = if let Some(actor) = &event.actor {
            if let Some(uid) = &actor.user_id {
                format!("user:{}", uid)
            } else if let Some(ip) = &event.source.ip {
                format!("ip:{}", ip)
            } else {
                format!("app:{}", event.app_id)
            }
        } else if let Some(ip) = &event.source.ip {
            format!("ip:{}", ip)
        } else {
            format!("app:{}", event.app_id)
        };

        // Increment hot state risk points for entity
        let _ = self
            .state
            .add_entity_risk(&target_entity, signal.risk_weight, 3600)
            .await?;

        let mut active = self.active_incidents.write().await;
        let mut history = self.incident_history.write().await;

        if let Some(existing) = active.get_mut(&target_entity) {
            if existing.status == IncidentStatus::Open || existing.status == IncidentStatus::Investigating {
                existing.add_signal(signal.clone(), Some(event.clone()));
                let updated = existing.clone();

                // Update in history as well
                if let Some(item) = history.iter_mut().find(|i| i.incident_id == updated.incident_id) {
                    *item = updated.clone();
                }

                warn!(
                    incident_id = %updated.incident_id,
                    target = %target_entity,
                    risk_score = updated.risk_score,
                    severity = ?updated.severity,
                    "Escalated existing security incident"
                );

                let _ = self.incident_tx.send(updated);
                return Ok(());
            }
        }

        // Otherwise create new Incident
        let incident = Incident::new(
            format!("{}: {}", signal.rule_name, target_entity),
            signal.description.clone(),
            signal.severity.clone(),
            target_entity.clone(),
            event.app_id.clone(),
            signal,
            event.clone(),
        );

        warn!(
            incident_id = %incident.incident_id,
            target = %target_entity,
            severity = ?incident.severity,
            "Created new security incident"
        );

        let inc_clone = incident.clone();
        active.insert(target_entity, incident.clone());
        history.push(incident);

        let _ = self.incident_tx.send(inc_clone);
        Ok(())
    }

    /// Retrieve all active (open / investigating) incidents.
    pub async fn get_active_incidents(&self) -> Vec<Incident> {
        let active = self.active_incidents.read().await;
        active.values().cloned().collect()
    }

    /// Retrieve all incidents (including resolved/contained historical ones).
    pub async fn get_all_incidents(&self) -> Vec<Incident> {
        let history = self.incident_history.read().await;
        history.clone()
    }

    /// Find an incident by its unique UUID.
    pub async fn get_incident_by_id(&self, id: Uuid) -> Option<Incident> {
        let history = self.incident_history.read().await;
        history.iter().find(|i| i.incident_id == id).cloned()
    }

    /// Update status of an incident (e.g., Contain, Resolve, FalsePositive).
    pub async fn update_incident_status(&self, id: Uuid, status: IncidentStatus) -> bool {
        let mut active = self.active_incidents.write().await;
        let mut history = self.incident_history.write().await;
        let mut found = false;
        let mut updated_incident = None;

        if let Some(item) = history.iter_mut().find(|i| i.incident_id == id) {
            item.status = status.clone();
            item.updated_at = chrono::Utc::now();
            found = true;
            updated_incident = Some(item.clone());
        }

        // If contained or resolved, remove from active map or update status
        for (_, inc) in active.iter_mut() {
            if inc.incident_id == id {
                inc.status = status.clone();
                inc.updated_at = chrono::Utc::now();
                break;
            }
        }

        if let Some(inc) = updated_incident {
            let _ = self.incident_tx.send(inc);
        }

        found
    }
}
