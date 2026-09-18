use async_trait::async_trait;
use security_control_plane_common::{SecurityEvent, Severity};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

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
        if matches!(event.severity, Severity::Medium | Severity::High | Severity::Critical) {
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
}

/// Memory-backed Durable Sink for local standalone runs and unit tests.
#[derive(Clone, Default)]
pub struct MemoryDurableSink {
    records: Arc<RwLock<Vec<SecurityEvent>>>,
}

impl MemoryDurableSink {
    pub fn new() -> Self {
        Self {
            records: Arc::new(RwLock::new(Vec::new())),
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
}
