use async_trait::async_trait;
use security_control_plane_common::SecurityEvent;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{broadcast, RwLock};

#[derive(Debug, Error)]
pub enum StreamError {
    #[error("Failed to publish event: {0}")]
    PublishError(String),

    #[error("Failed to read from event stream: {0}")]
    ConsumeError(String),

    #[error("Stream capacity exceeded (backpressure drop)")]
    CapacityExceeded,

    #[error("Stream serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

/// Abstract Producer interface for the decoupled Event Stream
#[async_trait]
pub trait EventStreamProducer: Send + Sync {
    async fn publish(&self, event: &SecurityEvent) -> Result<String, StreamError>;
    async fn publish_batch(&self, events: &[SecurityEvent]) -> Result<Vec<String>, StreamError>;
}

/// Abstract Consumer interface for the decoupled Event Stream
#[async_trait]
pub trait EventStreamConsumer: Send + Sync {
    async fn poll_events(&self, batch_size: usize, timeout_ms: u64) -> Result<Vec<SecurityEvent>, StreamError>;
}

/// High-throughput in-memory Event Stream implementation.
/// Ideal for standalone local testing, CI/CD, and low-latency single-node setups.
#[derive(Clone)]
pub struct MemoryEventStream {
    sender: broadcast::Sender<SecurityEvent>,
    backlog: Arc<RwLock<Vec<SecurityEvent>>>,
    max_backlog: usize,
}

impl MemoryEventStream {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self {
            sender,
            backlog: Arc::new(RwLock::new(Vec::with_capacity(capacity))),
            max_backlog: capacity,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<SecurityEvent> {
        self.sender.subscribe()
    }

    /// Returns the most recent `limit` events from the in-memory backlog
    /// without draining them. This is safe for read-only polling endpoints.
    pub async fn get_recent(&self, limit: usize) -> Vec<SecurityEvent> {
        let backlog = self.backlog.read().await;
        let start = if backlog.len() > limit {
            backlog.len() - limit
        } else {
            0
        };
        backlog[start..].to_vec()
    }
}

#[async_trait]
impl EventStreamProducer for MemoryEventStream {
    async fn publish(&self, event: &SecurityEvent) -> Result<String, StreamError> {
        let event_id_str = event.event_id.to_string();
        
        // Broadcast to active real-time subscribers (like WebSockets or Detector)
        let _ = self.sender.send(event.clone());

        // Retain in memory buffer for polling consumers
        let mut backlog = self.backlog.write().await;
        if backlog.len() >= self.max_backlog {
            backlog.remove(0); // Bounded ring behavior
        }
        backlog.push(event.clone());

        Ok(event_id_str)
    }

    async fn publish_batch(&self, events: &[SecurityEvent]) -> Result<Vec<String>, StreamError> {
        let mut ids = Vec::with_capacity(events.len());
        for ev in events {
            ids.push(self.publish(ev).await?);
        }
        Ok(ids)
    }
}

#[async_trait]
impl EventStreamConsumer for MemoryEventStream {
    async fn poll_events(&self, batch_size: usize, _timeout_ms: u64) -> Result<Vec<SecurityEvent>, StreamError> {
        let mut backlog = self.backlog.write().await;
        if backlog.is_empty() {
            return Ok(Vec::new());
        }

        let drain_count = batch_size.min(backlog.len());
        let batch: Vec<SecurityEvent> = backlog.drain(0..drain_count).collect();
        Ok(batch)
    }
}
