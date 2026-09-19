use security_control_plane_common::SecurityEvent;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityType {
    DatabaseRead,
    DatabaseWrite,
    NetworkConnect,
    FilesystemRead,
    FilesystemWrite,
    ProcessExecute,
    AdminOperation,
    SessionAuthenticate,
    DataExport,
}

impl CapabilityType {
    pub fn as_str(&self) -> &'static str {
        match self {
            CapabilityType::DatabaseRead => "database.read",
            CapabilityType::DatabaseWrite => "database.write",
            CapabilityType::NetworkConnect => "network.connect",
            CapabilityType::FilesystemRead => "filesystem.read",
            CapabilityType::FilesystemWrite => "filesystem.write",
            CapabilityType::ProcessExecute => "process.execute",
            CapabilityType::AdminOperation => "admin.operation",
            CapabilityType::SessionAuthenticate => "session.authenticate",
            CapabilityType::DataExport => "data.export",
        }
    }
}

/// Infer capabilities exercised by a given SecurityEvent
pub fn infer_capabilities(event: &SecurityEvent) -> Vec<CapabilityType> {
    let mut caps = Vec::new();

    // 1. Process / Kernel execution capabilities
    if event.source.process_name.is_some()
        || event.event_type == "kernel.process_exec"
        || event.source.sensor.sensor_type == security_control_plane_common::SensorType::Tetragon
    {
        caps.push(CapabilityType::ProcessExecute);
    }

    // 2. Authentication capabilities
    if event.event_type.starts_with("auth.")
        || event
            .action
            .as_ref()
            .and_then(|a| a.endpoint.as_deref())
            .map(|ep| ep.contains("/auth/") || ep.contains("/login"))
            .unwrap_or(false)
    {
        caps.push(CapabilityType::SessionAuthenticate);
    }

    // 3. Administrative capabilities
    if event.event_type.starts_with("admin.")
        || event
            .action
            .as_ref()
            .and_then(|a| a.endpoint.as_deref())
            .map(|ep| ep.starts_with("/admin") || ep.contains("/actuator") || ep.contains("/config"))
            .unwrap_or(false)
    {
        caps.push(CapabilityType::AdminOperation);
    }

    // 4. Data export capabilities
    if event.event_type.contains("export")
        || event
            .action
            .as_ref()
            .and_then(|a| a.endpoint.as_deref())
            .map(|ep| ep.contains("/export") || ep.contains("/dump") || ep.contains("/backup"))
            .unwrap_or(false)
    {
        caps.push(CapabilityType::DataExport);
    }

    // 5. Database read/write capabilities
    if let Some(res) = &event.resource {
        if let Some(rt) = &res.resource_type {
            if rt.contains("db") || rt.contains("database") || rt.contains("table") {
                if event.action.as_ref().map(|a| a.method.as_deref() == Some("GET")).unwrap_or(true) {
                    caps.push(CapabilityType::DatabaseRead);
                } else {
                    caps.push(CapabilityType::DatabaseWrite);
                }
            }
        }
    }

    // 6. Network connect capabilities (Hubble / Network flows)
    if event.source.sensor.sensor_type == security_control_plane_common::SensorType::Hubble
        || event.event_type == "network_flow"
    {
        caps.push(CapabilityType::NetworkConnect);
    }

    // 7. Filesystem capabilities (Falco file alerts)
    if event.event_type.contains("file") || event.event_type.contains("directory") {
        caps.push(CapabilityType::FilesystemRead);
    }

    caps
}
