use chrono::{DateTime, Utc};
use security_control_plane_common::{
    ActionContext, SecurityEvent, SensorMetadata, SensorType, Severity, SourceContext,
};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum HubbleParseError {
    #[error("Missing or invalid 'flow' object in Hubble payload")]
    MissingFlowObject,
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}

/// Adapter that transforms raw Cilium Hubble L3/L4/L7 flow logs into canonical SecurityEvents.
pub struct HubbleAdapter;

impl HubbleAdapter {
    /// Parses a raw Hubble flow JSON object into a normalized canonical SecurityEvent.
    pub fn parse_event(raw_json: &Value) -> Result<SecurityEvent, HubbleParseError> {
        let flow_val = raw_json
            .get("flow")
            .ok_or(HubbleParseError::MissingFlowObject)?;

        let node_name = raw_json
            .get("node_name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let timestamp_str = flow_val.get("time").and_then(|v| v.as_str());
        let timestamp = if let Some(t_str) = timestamp_str {
            DateTime::parse_from_rfc3339(t_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now())
        } else {
            Utc::now()
        };

        let verdict = flow_val
            .get("verdict")
            .and_then(|v| v.as_str())
            .unwrap_or("UNKNOWN");

        let drop_reason = flow_val
            .get("drop_reason_desc")
            .and_then(|d| d.as_str())
            .map(|s| s.to_string());

        let traffic_direction = flow_val
            .get("traffic_direction")
            .and_then(|t| t.as_str())
            .unwrap_or("EGRESS");

        let is_dropped = verdict == "DROPPED";

        let severity = if is_dropped {
            Severity::High
        } else {
            Severity::Low
        };

        // Extract IP & Ports
        let ip_val = flow_val.get("IP");
        let src_ip = ip_val
            .and_then(|i| i.get("source"))
            .and_then(|s| s.as_str())
            .map(|s| s.to_string());

        let dst_ip = ip_val
            .and_then(|i| i.get("destination"))
            .and_then(|d| d.as_str())
            .map(|s| s.to_string());

        let l4_val = flow_val.get("l4");
        let tcp_val = l4_val.and_then(|l| l.get("TCP"));
        let udp_val = l4_val.and_then(|l| l.get("UDP"));

        let (src_port, dst_port, protocol) = if let Some(tcp) = tcp_val {
            let sp = tcp.get("source_port").and_then(|p| p.as_u64()).map(|p| p as u16);
            let dp = tcp.get("destination_port").and_then(|p| p.as_u64()).map(|p| p as u16);
            (sp, dp, "TCP")
        } else if let Some(udp) = udp_val {
            let sp = udp.get("source_port").and_then(|p| p.as_u64()).map(|p| p as u16);
            let dp = udp.get("destination_port").and_then(|p| p.as_u64()).map(|p| p as u16);
            (sp, dp, "UDP")
        } else {
            (None, None, "IP")
        };

        // Extract source / destination workload
        let source_label_app = flow_val
            .get("source")
            .and_then(|s| s.get("labels"))
            .and_then(|l| l.as_array())
            .and_then(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .find_map(|s| {
                        if let Some(app) = s.strip_prefix("app=") {
                            Some(app)
                        } else if let Some(app) = s.strip_prefix("k8s:app=") {
                            Some(app)
                        } else {
                            None
                        }
                    })
            });

        let source_workload = flow_val
            .get("source")
            .and_then(|s| s.get("workloads"))
            .and_then(|w| w.as_array())
            .and_then(|arr| arr.first())
            .and_then(|item| item.get("name"))
            .and_then(|n| n.as_str());

        let source_pod = flow_val
            .get("source")
            .and_then(|s| s.get("pod_name"))
            .and_then(|p| p.as_str());

        let app_id = source_label_app
            .or(source_workload)
            .or(source_pod)
            .unwrap_or("hubble-monitored-service")
            .to_string();

        let endpoint = if let (Some(ref dst), Some(dp)) = (&dst_ip, dst_port) {
            format!("{}:{}", dst, dp)
        } else {
            dst_ip.clone().unwrap_or_else(|| "unknown:0".into())
        };

        let event = SecurityEvent {
            event_id: Uuid::new_v4(),
            timestamp,
            app_id,
            environment: "production".into(),
            event_type: format!("network.hubble.{}", verdict.to_lowercase()),
            severity,
            actor: None,
            source: SourceContext {
                ip: src_ip,
                port: src_port,
                user_agent: None,
                sensor: SensorMetadata {
                    sensor_type: SensorType::Hubble,
                    raw_event_type: format!("flow_{}", verdict),
                    sensor_id: node_name,
                    raw_payload: Some(raw_json.clone()),
                },
                container_id: None,
                pid: None,
                process_name: Some(format!("{}:{}", protocol, traffic_direction)),
            },
            action: Some(ActionContext {
                method: Some(traffic_direction.into()),
                endpoint: Some(endpoint),
                status_code: None,
                duration_us: None,
                is_success: !is_dropped,
                operation: Some(format!(
                    "{}: {} ({})",
                    verdict,
                    drop_reason.as_deref().unwrap_or("N/A"),
                    protocol
                )),
            }),
            resource: None,
            metadata: std::collections::HashMap::new(),
            is_security_significant: is_dropped,
        };

        Ok(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_hubble_dropped_flow() {
        let raw = json!({
            "flow": {
                "time": "2026-09-20T12:02:00Z",
                "verdict": "DROPPED",
                "drop_reason_desc": "POLICY_DENIED",
                "IP": {
                    "source": "10.0.1.50",
                    "destination": "198.51.100.200"
                },
                "l4": {
                    "TCP": {
                        "source_port": 54321,
                        "destination_port": 443
                    }
                },
                "source": {
                    "pod_name": "billing-service-789d-abc",
                    "workloads": [{ "name": "billing-service", "kind": "Deployment" }]
                },
                "traffic_direction": "EGRESS"
            },
            "node_name": "worker-k8s-01"
        });

        let event = HubbleAdapter::parse_event(&raw).expect("Failed to parse Hubble flow");
        assert_eq!(event.app_id, "billing-service");
        assert_eq!(event.severity, Severity::High);
        assert_eq!(event.source.sensor.sensor_type, SensorType::Hubble);
        assert_eq!(event.source.ip.as_deref(), Some("10.0.1.50"));
        assert_eq!(event.source.port, Some(54321));
        assert_eq!(event.action.as_ref().unwrap().endpoint.as_deref(), Some("198.51.100.200:443"));
        assert!(event.is_security_significant);
        assert!(!event.action.as_ref().unwrap().is_success);
    }
}
