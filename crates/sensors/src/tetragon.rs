use chrono::{DateTime, Utc};
use security_control_plane_common::{
    ActionContext, ActorContext, SecurityEvent, SensorMetadata, SensorType, Severity, SourceContext,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum TetragonParseError {
    #[error("Missing or invalid 'process_exec' or 'process_kprobe' event in Tetragon payload: {0}")]
    MissingEventField(String),
    #[error("Failed to parse timestamp from Tetragon event: {0}")]
    InvalidTimestamp(String),
    #[error("JSON deserialization error: {0}")]
    JsonError(#[from] serde_json::Error),
}

/// Cilium Tetragon Process execution telemetry payload structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TetragonProcessExec {
    pub process: Option<TetragonProcess>,
    pub parent: Option<TetragonProcess>,
    pub node_name: Option<String>,
    pub time: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TetragonProcess {
    pub exec_id: Option<String>,
    pub pid: Option<u32>,
    pub uid: Option<u32>,
    pub cwd: Option<String>,
    pub binary: Option<String>,
    pub arguments: Option<String>,
    pub flags: Option<String>,
    pub start_time: Option<String>,
    pub pod: Option<TetragonPod>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TetragonPod {
    pub namespace: Option<String>,
    pub name: Option<String>,
    pub container: Option<TetragonContainer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TetragonContainer {
    pub id: Option<String>,
    pub name: Option<String>,
    pub image: Option<TetragonImage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TetragonImage {
    pub id: Option<String>,
    pub name: Option<String>,
}

/// Adapter that transforms raw Cilium Tetragon JSON events into canonical SecurityEvents.
pub struct TetragonAdapter;

impl TetragonAdapter {
    /// Parses and normalizes a raw Tetragon JSON object or string into a canonical SecurityEvent.
    pub fn parse_event(raw_json: &Value) -> Result<SecurityEvent, TetragonParseError> {
        let node_name = raw_json
            .get("node_name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let timestamp_str = raw_json.get("time").and_then(|v| v.as_str());
        let timestamp = if let Some(t_str) = timestamp_str {
            DateTime::parse_from_rfc3339(t_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now())
        } else {
            Utc::now()
        };

        // 1. Check for process_exec event
        if let Some(exec_val) = raw_json.get("process_exec") {
            let proc_val = exec_val.get("process");
            let binary = proc_val
                .and_then(|p| p.get("binary"))
                .and_then(|b| b.as_str())
                .unwrap_or("unknown")
                .to_string();

            let arguments = proc_val
                .and_then(|p| p.get("arguments"))
                .and_then(|a| a.as_str())
                .map(|s| s.to_string());

            let pid = proc_val
                .and_then(|p| p.get("pid"))
                .and_then(|p| p.as_u64())
                .map(|p| p as u32);

            let uid = proc_val
                .and_then(|p| p.get("uid"))
                .and_then(|u| u.as_u64())
                .map(|u| u as u32);

            let pod_val = proc_val.and_then(|p| p.get("pod"));
            let container_val = pod_val.and_then(|p| p.get("container"));

            let container_id = container_val
                .and_then(|c| c.get("id"))
                .and_then(|i| i.as_str())
                .map(|s| s.to_string());

            let app_id = pod_val
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                .map(|name| Self::strip_k8s_suffix(name))
                .or_else(|| {
                    container_val
                        .and_then(|c| c.get("name"))
                        .and_then(|n| n.as_str())
                        .map(|s| s.to_string())
                })
                .unwrap_or_else(|| "container-workload".into());

            let is_container = container_id.is_some();

            // Detect high-risk container execution (e.g. shells, reverse shell utils)
            let (severity, is_suspicious) = Self::classify_binary(&binary, is_container);

            let event = SecurityEvent {
                event_id: Uuid::new_v4(),
                timestamp,
                app_id,
                environment: "production".into(),
                event_type: "kernel.process_exec".into(),
                severity,
                actor: uid.map(|u| ActorContext {
                    user_id: Some(format!("uid:{}", u)),
                    role: if u == 0 { Some("root".into()) } else { None },
                    session_id: None,
                    auth_method: None,
                    client_fingerprint: None,
                }),
                source: SourceContext {
                    ip: None,
                    port: None,
                    user_agent: None,
                    sensor: SensorMetadata {
                        sensor_type: SensorType::Tetragon,
                        raw_event_type: "process_exec".into(),
                        sensor_id: node_name,
                        raw_payload: Some(raw_json.clone()),
                    },
                    container_id,
                    pid,
                    process_name: Some(binary.clone()),
                },
                action: Some(ActionContext {
                    method: None,
                    endpoint: arguments.clone(),
                    status_code: None,
                    duration_us: None,
                    is_success: true,
                    operation: Some(format!("exec: {}", binary)),
                }),
                resource: None,
                metadata: std::collections::HashMap::new(),
                is_security_significant: is_suspicious,
            };

            return Ok(event);
        }

        // 2. Check for process_kprobe event (e.g., connect, openat)
        if let Some(kprobe_val) = raw_json.get("process_kprobe") {
            let func_name = kprobe_val
                .get("function_name")
                .and_then(|f| f.as_str())
                .unwrap_or("sys_kprobe")
                .to_string();

            let proc_val = kprobe_val.get("process");
            let binary = proc_val
                .and_then(|p| p.get("binary"))
                .and_then(|b| b.as_str())
                .unwrap_or("unknown")
                .to_string();

            let pid = proc_val
                .and_then(|p| p.get("pid"))
                .and_then(|p| p.as_u64())
                .map(|p| p as u32);

            let pod_val = proc_val.and_then(|p| p.get("pod"));
            let container_val = pod_val.and_then(|p| p.get("container"));
            let container_id = container_val
                .and_then(|c| c.get("id"))
                .and_then(|i| i.as_str())
                .map(|s| s.to_string());

            let app_id = container_val
                .and_then(|c| c.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("container-workload")
                .to_string();

            let event = SecurityEvent {
                event_id: Uuid::new_v4(),
                timestamp,
                app_id,
                environment: "production".into(),
                event_type: format!("kernel.kprobe.{}", func_name),
                severity: Severity::Medium,
                actor: None,
                source: SourceContext {
                    ip: None,
                    port: None,
                    user_agent: None,
                    sensor: SensorMetadata {
                        sensor_type: SensorType::Tetragon,
                        raw_event_type: "process_kprobe".into(),
                        sensor_id: node_name,
                        raw_payload: Some(raw_json.clone()),
                    },
                    container_id,
                    pid,
                    process_name: Some(binary),
                },
                action: Some(ActionContext {
                    method: None,
                    endpoint: Some(func_name.clone()),
                    status_code: None,
                    duration_us: None,
                    is_success: true,
                    operation: Some(format!("kprobe:{}", func_name)),
                }),
                resource: None,
                metadata: std::collections::HashMap::new(),
                is_security_significant: true,
            };

            return Ok(event);
        }

        Err(TetragonParseError::MissingEventField(
            "Neither 'process_exec' nor 'process_kprobe' found in Tetragon JSON".into(),
        ))
    }

    /// Strips Kubernetes deployment/replicaset hash suffixes from a pod name
    /// to recover the service name.
    /// e.g. "billing-service-64d8f-xyz12" → "billing-service"
    /// e.g. "billing-service-a3f1c" → "billing-service"
    fn strip_k8s_suffix(pod_name: &str) -> String {
        let parts: Vec<&str> = pod_name.split('-').collect();
        if parts.len() <= 1 {
            return pod_name.to_string();
        }
        // Strip trailing segments that look like K8s hashes
        // (alphanumeric, 4-10 chars, must contain at least one digit)
        let mut end = parts.len();
        while end > 1 {
            let seg = parts[end - 1];
            let looks_like_hash = seg.len() >= 4
                && seg.len() <= 10
                && seg.chars().all(|c| c.is_ascii_alphanumeric())
                && seg.chars().any(|c| c.is_ascii_digit());
            if looks_like_hash {
                end -= 1;
            } else {
                break;
            }
        }
        if end == 0 {
            pod_name.to_string()
        } else {
            parts[..end].join("-")
        }
    }

    /// Classifies the binary execution into severity and suspicion flag.
    fn classify_binary(binary: &str, in_container: bool) -> (Severity, bool) {
        let b = binary.to_lowercase();
        if b.ends_with("/sh") || b.ends_with("/bash") || b.ends_with("/zsh") || b == "sh" || b == "bash" {
            if in_container {
                // Shell inside a container is an instant critical security event
                (Severity::Critical, true)
            } else {
                (Severity::Medium, false)
            }
        } else if b.ends_with("/nc") || b.ends_with("/ncat") || b.ends_with("/socat") || b == "nc" {
            (Severity::Critical, true)
        } else if b.ends_with("/curl") || b.ends_with("/wget") || b.ends_with("/python") {
            (Severity::High, in_container)
        } else {
            (Severity::Low, false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_tetragon_shell_exec() {
        let raw = json!({
            "process_exec": {
                "process": {
                    "exec_id": "b3JnL2FwcC0xMjM=",
                    "pid": 4821,
                    "uid": 0,
                    "binary": "/bin/sh",
                    "arguments": "-i",
                    "pod": {
                        "namespace": "prod",
                        "name": "billing-deployment-64d8f-xyz12",
                        "container": {
                            "id": "containerd://a83f9104c99e",
                            "name": "billing-app"
                        }
                    }
                }
            },
            "node_name": "worker-k8s-01",
            "time": "2026-09-20T12:00:00Z"
        });

        let event = TetragonAdapter::parse_event(&raw).expect("Failed to parse Tetragon event");
        assert_eq!(event.app_id, "billing-deployment");
        assert_eq!(event.severity, Severity::Critical);
        assert!(event.is_security_significant);
        assert_eq!(event.source.sensor.sensor_type, SensorType::Tetragon);
        assert_eq!(event.source.container_id.as_deref(), Some("containerd://a83f9104c99e"));
        assert_eq!(event.source.pid, Some(4821));
        assert_eq!(event.source.process_name.as_deref(), Some("/bin/sh"));
        assert_eq!(event.action.as_ref().unwrap().endpoint.as_deref(), Some("-i"));
    }

    #[test]
    fn test_parse_tetragon_kprobe() {
        let raw = json!({
            "process_kprobe": {
                "function_name": "sys_enter_connect",
                "process": {
                    "pid": 5012,
                    "binary": "/usr/bin/curl",
                    "pod": {
                        "container": {
                            "id": "containerd://bb8812c",
                            "name": "crm-app"
                        }
                    }
                }
            },
            "node_name": "worker-k8s-02",
            "time": "2026-09-20T12:05:00Z"
        });

        let event = TetragonAdapter::parse_event(&raw).expect("Failed to parse Tetragon kprobe");
        assert_eq!(event.app_id, "crm-app");
        assert_eq!(event.event_type, "kernel.kprobe.sys_enter_connect");
        assert_eq!(event.source.pid, Some(5012));
    }
}
