pub mod guard;

pub use guard::ContainmentGuard;
use chrono::Utc;
use crossbeam_channel::{bounded, Receiver, Sender};
use security_control_plane_common::{
    ActionContext, ActorContext, SecurityEvent, SensorMetadata, SensorType, Severity, SourceContext,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error};
use uuid::Uuid;

#[derive(Clone)]
pub struct SecurityAgentConfig {
    pub app_id: String,
    pub environment: String,
    pub control_plane_url: String,
    pub queue_capacity: usize,
    pub batch_size: usize,
    pub flush_interval: Duration,
}

impl Default for SecurityAgentConfig {
    fn default() -> Self {
        Self {
            app_id: "rust-service".into(),
            environment: "production".into(),
            control_plane_url: "http://localhost:8080/api/v1/telemetry".into(),
            queue_capacity: 10_000,
            batch_size: 50,
            flush_interval: Duration::from_millis(500),
        }
    }
}

pub struct SecurityAgentClient {
    config: SecurityAgentConfig,
    sender: Sender<SecurityEvent>,
    dropped_events: Arc<AtomicUsize>,
}

impl SecurityAgentClient {
    pub fn start(config: SecurityAgentConfig) -> Self {
        let (sender, receiver) = bounded(config.queue_capacity);
        let dropped_events = Arc::new(AtomicUsize::new(0));

        let worker_config = config.clone();
        let worker_dropped = Arc::clone(&dropped_events);

        // Spawn independent OS thread for background flushing
        std::thread::Builder::new()
            .name("security-telemetry-emitter".into())
            .spawn(move || {
                run_flush_worker(worker_config, receiver, worker_dropped);
            })
            .expect("failed to spawn security telemetry emitter thread");

        Self {
            config,
            sender,
            dropped_events,
        }
    }

    /// Records a security event in sub-microsecond non-blocking time.
    /// If the queue is full, fails open and increments dropped counter.
    pub fn record_event_non_blocking(
        &self,
        event_type: impl Into<String>,
        source_ip: Option<String>,
        method: Option<String>,
        endpoint: Option<String>,
        status_code: Option<u16>,
        duration_us: Option<u64>,
        user_id: Option<String>,
        session_id: Option<String>,
        is_security_significant: bool,
    ) {
        let is_success = status_code.map(|c| c < 400).unwrap_or(true);
        let event = SecurityEvent {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            app_id: self.config.app_id.clone(),
            environment: self.config.environment.clone(),
            event_type: event_type.into(),
            severity: if is_security_significant {
                Severity::Medium
            } else {
                Severity::Low
            },
            actor: if user_id.is_some() || session_id.is_some() {
                Some(ActorContext {
                    user_id,
                    role: None,
                    session_id,
                    auth_method: None,
                    client_fingerprint: None,
                })
            } else {
                None
            },
            source: SourceContext {
                ip: source_ip,
                port: None,
                user_agent: None,
                sensor: SensorMetadata {
                    sensor_type: SensorType::Agent,
                    raw_event_type: "rust_agent_sdk".into(),
                    sensor_id: None,
                    raw_payload: None,
                },
                container_id: None,
                pid: None,
                process_name: None,
            },
            action: Some(ActionContext {
                method,
                endpoint,
                status_code,
                duration_us,
                is_success,
                operation: None,
            }),
            resource: None,
            metadata: std::collections::HashMap::new(),
            is_security_significant,
        };

        if self.sender.try_send(event).is_err() {
            self.dropped_events.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn dropped_events_count(&self) -> usize {
        self.dropped_events.load(Ordering::Relaxed)
    }
}

fn run_flush_worker(
    config: SecurityAgentConfig,
    receiver: Receiver<SecurityEvent>,
    _dropped: Arc<AtomicUsize>,
) {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap_or_else(|_| reqwest::blocking::Client::new());

    let mut batch = Vec::with_capacity(config.batch_size);

    loop {
        // Collect events up to batch size or flush interval timeout
        match receiver.recv_timeout(config.flush_interval) {
            Ok(event) => {
                batch.push(event);
                while batch.len() < config.batch_size {
                    match receiver.try_recv() {
                        Ok(ev) => batch.push(ev),
                        Err(_) => break,
                    }
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                // Interval elapsed, flush whatever is in batch
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                // Application terminating
                if !batch.is_empty() {
                    let _ = client.post(&config.control_plane_url).json(&batch).send();
                }
                break;
            }
        }

        if !batch.is_empty() {
            let res = client.post(&config.control_plane_url).json(&batch).send();
            match res {
                Ok(response) => {
                    debug!(status = ?response.status(), count = batch.len(), "Telemetry batch transmitted");
                }
                Err(err) => {
                    // Controller outage must NEVER block or crash the application
                    error!(error = %err, "Failed to transmit telemetry batch (failing open)");
                }
            }
            batch.clear();
        }
    }
}
