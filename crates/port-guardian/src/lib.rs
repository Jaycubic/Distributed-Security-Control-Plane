mod error;
mod registry;
mod scan_detector;

pub use error::PortGuardianError;
pub use registry::{PortBinding, PortRegistry};
pub use scan_detector::PortScanDetector;

use security_control_plane_common::SecurityEvent;
use security_control_plane_engine::HotStateStore;
use serde_json::Value;
use std::sync::Arc;

pub struct PortGuardian {
    registry: Arc<PortRegistry>,
    detector: PortScanDetector,
}

impl PortGuardian {
    pub fn new(hot_state: Arc<dyn HotStateStore>) -> Self {
        Self {
            registry: Arc::new(PortRegistry::new()),
            detector: PortScanDetector::new(hot_state),
        }
    }

    pub fn registry(&self) -> &Arc<PortRegistry> {
        &self.registry
    }

    pub async fn process_event(
        &self,
        event: &SecurityEvent,
    ) -> Result<SecurityEvent, PortGuardianError> {
        match event.event_type.as_str() {
            "kernel.net.bind" => {
                let Some(port) = event.source.port else {
                    return Ok(event.clone());
                };
                self.registry
                    .record_binding(PortBinding {
                        port,
                        pid: event.source.pid,
                        process_name: event.source.process_name.clone(),
                        bound_at: event.timestamp,
                        is_active: true,
                    })
                    .await;
            }
            "kernel.net.connect" | "kernel.net.accept" => {
                let Some(ip) = event.source.ip.as_deref() else {
                    return Ok(event.clone());
                };
                let Some(port) = event
                    .metadata
                    .get("dst_port")
                    .and_then(Value::as_u64)
                    .and_then(|value| u16::try_from(value).ok())
                    .or(event.source.port)
                else {
                    return Ok(event.clone());
                };

                if self.registry.is_registered(port).await {
                    if let Some(signal) = self
                        .detector
                        .observe(ip, port, event.timestamp.timestamp_millis())
                        .await?
                    {
                        let mut enriched = event.clone();
                        enriched
                            .metadata
                            .insert("port_scan_signal".to_string(), Value::String(signal));
                        enriched.severity = if enriched
                            .metadata
                            .get("port_scan_signal")
                            .and_then(Value::as_str)
                            .is_some_and(|signal| signal.starts_with("Port scan detected"))
                        {
                            security_control_plane_common::Severity::Critical
                        } else {
                            security_control_plane_common::Severity::High
                        };
                        enriched.is_security_significant = true;
                        return Ok(enriched);
                    }
                }
            }
            _ => {}
        }

        Ok(event.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use security_control_plane_common::{SensorMetadata, SensorType, SourceContext};
    use security_control_plane_engine::MemoryHotState;

    fn event(event_type: &str, ip: Option<&str>, port: u16) -> SecurityEvent {
        SecurityEvent::new(
            "test-host",
            "test",
            event_type,
            SourceContext {
                ip: ip.map(str::to_string),
                port: Some(port),
                user_agent: None,
                sensor: SensorMetadata {
                    sensor_type: SensorType::NativeSensor,
                    raw_event_type: event_type.to_string(),
                    sensor_id: None,
                    raw_payload: None,
                },
                container_id: None,
                pid: Some(1000),
                process_name: Some("nginx".into()),
            },
        )
    }

    #[tokio::test]
    async fn only_registered_ports_contribute_to_scans() {
        let guardian = PortGuardian::new(Arc::new(MemoryHotState::new()));
        let bind = event("kernel.net.bind", None, 8080);
        guardian.process_event(&bind).await.expect("bind event");

        let mut event = event("kernel.net.connect", Some("192.0.2.5"), 8081);
        event.timestamp = Utc::now();
        for _ in 0..20 {
            let result = guardian.process_event(&event).await.expect("connect event");
            assert!(!result.metadata.contains_key("port_scan_signal"));
        }
    }

    #[tokio::test]
    async fn registered_connections_are_enriched_after_threshold() {
        let guardian = PortGuardian::new(Arc::new(MemoryHotState::new()));
        for port in 8000..8015 {
            let bind = event("kernel.net.bind", None, port);
            guardian.process_event(&bind).await.expect("bind event");
        }

        let mut last_event = None;
        for port in 8000..8015 {
            let connect = event("kernel.net.connect", Some("192.0.2.6"), port);
            last_event = Some(
                guardian
                    .process_event(&connect)
                    .await
                    .expect("connect event"),
            );
        }

        let enriched = last_event.expect("at least one connection");
        assert!(enriched.metadata.contains_key("port_scan_signal"));
        assert!(enriched.is_security_significant);
        assert_eq!(
            enriched.severity,
            security_control_plane_common::Severity::Critical
        );
    }
}
