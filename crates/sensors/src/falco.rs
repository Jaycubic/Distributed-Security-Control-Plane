use chrono::{DateTime, Utc};
use security_control_plane_common::{
    ActionContext, ActorContext, SecurityEvent, SensorMetadata, SensorType, Severity, SourceContext,
};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum FalcoParseError {
    #[error("Missing required field '{0}' in Falco alert payload")]
    MissingField(&'static str),
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}

/// Adapter that transforms raw Falco runtime security alerts into canonical SecurityEvents.
pub struct FalcoAdapter;

impl FalcoAdapter {
    /// Parses a raw Falco JSON alert into a normalized canonical SecurityEvent.
    pub fn parse_event(raw_json: &Value) -> Result<SecurityEvent, FalcoParseError> {
        let rule = raw_json
            .get("rule")
            .and_then(|r| r.as_str())
            .ok_or(FalcoParseError::MissingField("rule"))?
            .to_string();

        let priority_str = raw_json
            .get("priority")
            .and_then(|p| p.as_str())
            .unwrap_or("Notice");

        let severity = Self::map_priority(priority_str);

        let timestamp_str = raw_json.get("time").and_then(|v| v.as_str());
        let timestamp = if let Some(t_str) = timestamp_str {
            DateTime::parse_from_rfc3339(t_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now())
        } else {
            Utc::now()
        };

        let output_fields = raw_json.get("output_fields");

        // Extract container fields
        let container_id = output_fields
            .and_then(|f| f.get("container.id"))
            .and_then(|c| c.as_str())
            .map(|s| s.to_string());

        let app_id = output_fields
            .and_then(|f| f.get("container.name"))
            .and_then(|n| n.as_str())
            .or_else(|| output_fields.and_then(|f| f.get("k8s.pod.name")).and_then(|n| n.as_str()))
            .unwrap_or("falco-monitored-workload")
            .to_string();

        // Extract process fields
        let process_name = output_fields
            .and_then(|f| f.get("proc.name"))
            .and_then(|p| p.as_str())
            .map(|s| s.to_string());

        let cmdline = output_fields
            .and_then(|f| f.get("proc.cmdline"))
            .and_then(|c| c.as_str())
            .map(|s| s.to_string());

        let pid = output_fields
            .and_then(|f| f.get("proc.pid"))
            .and_then(|p| p.as_u64())
            .map(|p| p as u32);

        let user_name = output_fields
            .and_then(|f| f.get("user.name"))
            .and_then(|u| u.as_str())
            .map(|s| s.to_string());

        // Extract network fields if present
        let rip = output_fields
            .and_then(|f| f.get("fd.rip"))
            .and_then(|ip| ip.as_str())
            .map(|s| s.to_string());

        let rport = output_fields
            .and_then(|f| f.get("fd.rport"))
            .and_then(|p| p.as_u64())
            .map(|p| p as u16);

        let is_security_significant = severity != Severity::Low;

        let event = SecurityEvent {
            event_id: Uuid::new_v4(),
            timestamp,
            app_id,
            environment: "production".into(),
            event_type: format!("runtime.falco.{}", rule.to_lowercase().replace(' ', "_")),
            severity,
            actor: user_name.map(|u| ActorContext {
                user_id: Some(u.clone()),
                role: if u == "root" { Some("root".into()) } else { None },
                session_id: None,
                auth_method: None,
                client_fingerprint: None,
            }),
            source: SourceContext {
                ip: rip,
                port: rport,
                user_agent: None,
                sensor: SensorMetadata {
                    sensor_type: SensorType::Falco,
                    raw_event_type: "rule_alert".into(),
                    sensor_id: Some("falco-engine".into()),
                    raw_payload: Some(raw_json.clone()),
                },
                container_id,
                pid,
                process_name,
            },
            action: Some(ActionContext {
                method: None,
                endpoint: cmdline,
                status_code: None,
                duration_us: None,
                is_success: false,
                operation: Some(rule),
            }),
            resource: None,
            metadata: std::collections::HashMap::new(),
            is_security_significant,
        };

        Ok(event)
    }

    /// Maps standard Falco syslog priorities to canonical Severity levels.
    fn map_priority(priority: &str) -> Severity {
        match priority.to_lowercase().as_str() {
            "emergency" | "alert" | "critical" => Severity::Critical,
            "error" | "warning" => Severity::High,
            "notice" => Severity::Medium,
            _ => Severity::Low,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_falco_alert() {
        let raw = json!({
            "uuid": "4c45a6c1-5c3b-483d-9be2-44a69b764264",
            "time": "2026-09-20T12:01:00Z",
            "rule": "Terminal shell in container",
            "priority": "Critical",
            "output": "A shell was spawned in container (user=root container_id=b43f9a12c cmdline=sh -i)",
            "output_fields": {
                "container.id": "b43f9a12c",
                "container.name": "billing-app",
                "proc.name": "sh",
                "proc.pid": 2841,
                "proc.cmdline": "sh -i",
                "user.name": "root",
                "fd.rip": "198.51.100.200",
                "fd.rport": 443
            },
            "source": "syscall"
        });

        let event = FalcoAdapter::parse_event(&raw).expect("Failed to parse Falco alert");
        assert_eq!(event.app_id, "billing-app");
        assert_eq!(event.severity, Severity::Critical);
        assert_eq!(event.source.sensor.sensor_type, SensorType::Falco);
        assert_eq!(event.source.container_id.as_deref(), Some("b43f9a12c"));
        assert_eq!(event.source.pid, Some(2841));
        assert_eq!(event.source.ip.as_deref(), Some("198.51.100.200"));
        assert_eq!(event.source.port, Some(443));
        assert!(event.is_security_significant);
    }
}
