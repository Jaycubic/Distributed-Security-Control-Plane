use async_trait::async_trait;
use security_control_plane_common::{SecurityEvent, Severity, SignedContainmentCommand};
use security_control_plane_engine::Incident;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[cfg(feature = "standalone")]
mod sqlite;
#[cfg(feature = "standalone")]
pub use sqlite::SqliteDurableSink;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

/// Evaluates whether an event qualifies for persistent database storage
/// to prevent flooding PostgreSQL with high-volume benign telemetry.
pub struct PersistenceFilter;

impl PersistenceFilter {
    pub fn should_persist(event: &SecurityEvent) -> bool {
        // 1. Explicitly flagged as security significant
        if event.is_security_significant {
            return true;
        }

        // 2. High severity anomalies
        if matches!(
            event.severity,
            Severity::Medium | Severity::High | Severity::Critical
        ) {
            return true;
        }

        // 3. Security-relevant event categories
        let t = event.event_type.to_lowercase();
        if t.starts_with("auth.")
            || t.starts_with("admin.")
            || t.starts_with("privilege.")
            || t.starts_with("incident.")
            || t.starts_with("containment.")
        {
            return true;
        }

        // 4. HTTP authentication/authorization failures
        if let Some(action) = &event.action {
            if let Some(status) = action.status_code {
                if status == 401 || status == 403 {
                    return true;
                }
            }
        }

        false
    }
}

#[async_trait]
pub trait DurableEventSink: Send + Sync {
    async fn save_batch(&self, events: &[SecurityEvent]) -> Result<usize, StorageError>;
    async fn get_recent_events(&self, limit: usize) -> Result<Vec<SecurityEvent>, StorageError>;
    async fn save_incident(&self, incident: &Incident) -> Result<(), StorageError>;
    async fn get_incidents(&self) -> Result<Vec<Incident>, StorageError>;
    async fn save_containment_command(
        &self,
        command: &SignedContainmentCommand,
    ) -> Result<(), StorageError>;
    async fn get_containment_commands(&self)
        -> Result<Vec<SignedContainmentCommand>, StorageError>;
}

/// Memory-backed Durable Sink for local standalone runs and unit tests.
#[derive(Clone, Default)]
pub struct MemoryDurableSink {
    records: Arc<RwLock<Vec<SecurityEvent>>>,
    incidents: Arc<RwLock<HashMap<uuid::Uuid, Incident>>>,
    commands: Arc<RwLock<HashMap<uuid::Uuid, SignedContainmentCommand>>>,
}

impl MemoryDurableSink {
    pub fn new() -> Self {
        Self {
            records: Arc::new(RwLock::new(Vec::new())),
            incidents: Arc::new(RwLock::new(HashMap::new())),
            commands: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl DurableEventSink for MemoryDurableSink {
    async fn save_batch(&self, events: &[SecurityEvent]) -> Result<usize, StorageError> {
        let mut to_save = Vec::new();
        for ev in events {
            if PersistenceFilter::should_persist(ev) {
                to_save.push(ev.clone());
            }
        }

        let saved_count = to_save.len();
        if saved_count > 0 {
            let mut store = self.records.write().await;
            store.extend(to_save);
        }

        Ok(saved_count)
    }

    async fn get_recent_events(&self, limit: usize) -> Result<Vec<SecurityEvent>, StorageError> {
        let store = self.records.read().await;
        let start = if store.len() > limit {
            store.len() - limit
        } else {
            0
        };
        Ok(store[start..].to_vec())
    }

    async fn save_incident(&self, incident: &Incident) -> Result<(), StorageError> {
        self.incidents
            .write()
            .await
            .insert(incident.incident_id, incident.clone());
        Ok(())
    }

    async fn get_incidents(&self) -> Result<Vec<Incident>, StorageError> {
        Ok(self.incidents.read().await.values().cloned().collect())
    }

    async fn save_containment_command(
        &self,
        command: &SignedContainmentCommand,
    ) -> Result<(), StorageError> {
        self.commands
            .write()
            .await
            .insert(command.command_id, command.clone());
        Ok(())
    }

    async fn get_containment_commands(
        &self,
    ) -> Result<Vec<SignedContainmentCommand>, StorageError> {
        Ok(self.commands.read().await.values().cloned().collect())
    }
}
