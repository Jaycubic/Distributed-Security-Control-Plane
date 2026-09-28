use security_control_plane_common::{
    SecurityEvent, SensorMetadata, SensorType, Severity, SourceContext,
};
use security_control_plane_sensor_native_common::{
    KernelEventKind, KernelExecEvent, KernelNetEvent,
};
use std::net::Ipv4Addr;

use crate::process_info::{read_exe_path, read_ppid};

pub struct KernelEventNormalizer {
    /// Identifies the host this sensor runs on. Used as app_id in SecurityEvent.
    pub hostname: String,
    /// Sensor ID injected into SensorMetadata for traceability.
    pub sensor_id: String,
}

impl KernelEventNormalizer {
    pub fn new(hostname: impl Into<String>) -> Self {
        let hostname = hostname.into();
        let sensor_id = format!("native-sensor-{}", hostname);
        Self {
            hostname,
            sensor_id,
        }
    }

    pub fn normalize_exec(&self, ev: &KernelExecEvent) -> SecurityEvent {
        let filename = null_terminated_str(&ev.filename);
        let comm = null_terminated_str(&ev.comm);
        let ppid = read_ppid(ev.pid);
        let exe_path = read_exe_path(ev.pid).unwrap_or_else(|| filename.to_string());

        let mut event = SecurityEvent::new(
            self.hostname.clone(),
            "production",
            "kernel.execve",
            SourceContext {
                ip: None,
                port: None,
                user_agent: None,
                sensor: SensorMetadata {
                    sensor_type: SensorType::NativeSensor,
                    raw_event_type: "execve".to_string(),
                    sensor_id: Some(self.sensor_id.clone()),
                    raw_payload: None,
                },
                container_id: None,
                pid: Some(ev.pid),
                process_name: Some(exe_path),
            },
        );

        event.severity = classify_exec_severity(filename, ev.uid);
        event.is_security_significant = event.severity >= Severity::Medium;

        event.metadata.insert(
            "ppid".to_string(),
            serde_json::Value::Number(serde_json::Number::from(ppid)),
        );
        event.metadata.insert(
            "comm".to_string(),
            serde_json::Value::String(comm.to_string()),
        );
        event.metadata.insert(
            "uid".to_string(),
            serde_json::Value::Number(serde_json::Number::from(ev.uid)),
        );
        event.metadata.insert(
            "filename".to_string(),
            serde_json::Value::String(filename.to_string()),
        );

        event
    }

    pub fn normalize_net(&self, ev: &KernelNetEvent) -> SecurityEvent {
        let comm = null_terminated_str(&ev.comm);
        let ppid = read_ppid(ev.pid);

        let kind = KernelEventKind::from_u32(ev.kind);
        let event_type = match kind {
            Some(KernelEventKind::Connect) => "kernel.net.connect",
            Some(KernelEventKind::Bind) => "kernel.net.bind",
            Some(KernelEventKind::Accept) => "kernel.net.accept",
            _ => "kernel.net.unknown",
        };

        let (remote_ip, _local_ip) = if ev.sa_family == 2 {
            (
                Some(Ipv4Addr::from(ev.dst_ip4).to_string()),
                Some(Ipv4Addr::from(ev.src_ip4).to_string()),
            )
        } else {
            (None, None)
        };

        let mut event = SecurityEvent::new(
            self.hostname.clone(),
            "production",
            event_type,
            SourceContext {
                ip: remote_ip,
                port: Some(ev.dst_port),
                user_agent: None,
                sensor: SensorMetadata {
                    sensor_type: SensorType::NativeSensor,
                    raw_event_type: event_type.to_string(),
                    sensor_id: Some(self.sensor_id.clone()),
                    raw_payload: None,
                },
                container_id: None,
                pid: Some(ev.pid),
                process_name: Some(comm.to_string()),
            },
        );

        event.metadata.insert(
            "sa_family".to_string(),
            serde_json::Value::Number(serde_json::Number::from(ev.sa_family)),
        );
        event.metadata.insert(
            "src_port".to_string(),
            serde_json::Value::Number(serde_json::Number::from(ev.src_port)),
        );
        event.metadata.insert(
            "dst_port".to_string(),
            serde_json::Value::Number(serde_json::Number::from(ev.dst_port)),
        );
        event.metadata.insert(
            "uid".to_string(),
            serde_json::Value::Number(serde_json::Number::from(ev.uid)),
        );
        event.metadata.insert(
            "comm".to_string(),
            serde_json::Value::String(comm.to_string()),
        );
        event.metadata.insert(
            "ppid".to_string(),
            serde_json::Value::Number(serde_json::Number::from(ppid)),
        );

        if kind == Some(KernelEventKind::Bind) {
            event.is_security_significant = true;
        }

        event
    }
}

/// Classify severity of an execve based on the binary path and user.
fn classify_exec_severity(filename: &str, uid: u32) -> Severity {
    const HIGH_RISK_BINARIES: &[&str] = &[
        "/bin/sh", "/bin/bash", "/usr/bin/bash", "/bin/dash", "nc", "ncat", "netcat", "socat",
        "curl", "wget", "python", "python3", "perl", "ruby",
    ];
    const CRITICAL_BINARIES: &[&str] = &[
        "sudo", "su", "passwd", "chpasswd", "visudo", "nsenter", "unshare", "ptrace",
    ];

    let name = filename.rsplit('/').next().unwrap_or(filename);

    if CRITICAL_BINARIES
        .iter()
        .any(|&b| name == b || filename.ends_with(b))
    {
        return Severity::High;
    }
    if HIGH_RISK_BINARIES
        .iter()
        .any(|&b| name == b || filename.ends_with(b))
    {
        return if uid == 0 {
            Severity::Critical
        } else {
            Severity::Medium
        };
    }
    Severity::Low
}

/// Reads a null-terminated C string from a fixed-length byte slice.
pub fn null_terminated_str(bytes: &[u8]) -> &str {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..end]).unwrap_or("<invalid-utf8>")
}
