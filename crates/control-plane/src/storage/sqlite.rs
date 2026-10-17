use super::{DurableEventSink, PersistenceFilter, StorageError};
use async_trait::async_trait;
use rusqlite::{params, Connection};
use security_control_plane_common::{SecurityEvent, SignedContainmentCommand};
use security_control_plane_engine::Incident;
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct SqliteDurableSink {
    connection: Arc<Mutex<Connection>>,
}

impl SqliteDurableSink {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let path = path.as_ref();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)
                .map_err(|err| StorageError::DatabaseError(err.to_string()))?;
        }
        let connection =
            Connection::open(path).map_err(|err| StorageError::DatabaseError(err.to_string()))?;
        Self::from_connection(connection)
    }

    pub fn in_memory() -> Result<Self, StorageError> {
        let connection = Connection::open_in_memory()
            .map_err(|err| StorageError::DatabaseError(err.to_string()))?;
        Self::from_connection(connection)
    }

    fn from_connection(connection: Connection) -> Result<Self, StorageError> {
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA foreign_keys = ON;
                 CREATE TABLE IF NOT EXISTS security_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    app_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS containment_commands (
                    command_id TEXT PRIMARY KEY,
                    action TEXT NOT NULL,
                    target_entity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    issued_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                 );",
            )
            .map_err(|err| StorageError::DatabaseError(err.to_string()))?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    async fn run_blocking<T, F>(&self, operation: F) -> Result<T, StorageError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T, StorageError> + Send + 'static,
    {
        let connection = Arc::clone(&self.connection);
        tokio::task::spawn_blocking(move || {
            let mut connection = connection
                .lock()
                .map_err(|_| StorageError::DatabaseError("SQLite lock poisoned".into()))?;
            operation(&mut connection)
        })
        .await
        .map_err(|err| StorageError::DatabaseError(err.to_string()))?
    }
}

#[async_trait]
impl DurableEventSink for SqliteDurableSink {
    async fn save_batch(&self, events: &[SecurityEvent]) -> Result<usize, StorageError> {
        let events: Vec<_> = events
            .iter()
            .filter(|event| PersistenceFilter::should_persist(event))
            .cloned()
            .collect();
        self.run_blocking(move |connection| {
            let transaction = connection
                .transaction()
                .map_err(|err| StorageError::DatabaseError(err.to_string()))?;
            for event in &events {
                let payload = serde_json::to_string(event)?;
                let severity = enum_string(&event.severity)?;
                transaction
                    .execute(
                        "INSERT INTO security_events
                         (event_id, timestamp, app_id, event_type, severity, payload_json)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                         ON CONFLICT(event_id) DO UPDATE SET payload_json = excluded.payload_json",
                        params![
                            event.event_id.to_string(),
                            event.timestamp.to_rfc3339(),
                            event.app_id,
                            event.event_type,
                            severity,
                            payload,
                        ],
                    )
                    .map_err(|err| StorageError::DatabaseError(err.to_string()))?;
            }
            transaction
                .commit()
                .map_err(|err| StorageError::DatabaseError(err.to_string()))?;
            Ok(events.len())
        })
        .await
    }

    async fn get_recent_events(&self, limit: usize) -> Result<Vec<SecurityEvent>, StorageError> {
        let limit = i64::try_from(limit)
            .map_err(|_| StorageError::DatabaseError("event limit exceeds SQLite range".into()))?;
        self.run_blocking(move |connection| {
            let mut statement = connection
                .prepare(
                    "SELECT payload_json FROM security_events ORDER BY timestamp DESC LIMIT ?1",
                )
                .map_err(|err| StorageError::DatabaseError(err.to_string()))?;
            let rows = statement
                .query_map([limit as i64], |row| row.get::<_, String>(0))
                .map_err(|err| StorageError::DatabaseError(err.to_string()))?;
            let mut events = rows
                .map(|row| {
                    let payload =
                        row.map_err(|err| StorageError::DatabaseError(err.to_string()))?;
                    serde_json::from_str(&payload).map_err(StorageError::from)
                })
                .collect::<Result<Vec<_>, _>>()?;
            events.reverse();
            Ok(events)
        })
        .await
    }

    async fn save_incident(&self, incident: &Incident) -> Result<(), StorageError> {
        let incident = incident.clone();
        self.run_blocking(move |connection| {
            let payload = serde_json::to_string(&incident)?;
            let severity = enum_string(&incident.severity)?;
            let status = enum_string(&incident.status)?;
            connection
                .execute(
                    "INSERT INTO incidents
                     (incident_id, title, severity, status, risk_score, created_at, payload_json)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                     ON CONFLICT(incident_id) DO UPDATE SET
                        title = excluded.title,
                        severity = excluded.severity,
                        status = excluded.status,
                        risk_score = excluded.risk_score,
                        payload_json = excluded.payload_json",
                    params![
                        incident.incident_id.to_string(),
                        incident.title,
                        severity,
                        status,
                        incident.risk_score,
                        incident.created_at.to_rfc3339(),
                        payload,
                    ],
                )
                .map_err(|err| StorageError::DatabaseError(err.to_string()))?;
            Ok(())
        })
        .await
    }

    async fn get_incidents(&self) -> Result<Vec<Incident>, StorageError> {
        self.run_blocking(move |connection| {
            let mut statement = connection
                .prepare("SELECT payload_json FROM incidents ORDER BY created_at DESC")
                .map_err(|err| StorageError::DatabaseError(err.to_string()))?;
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(|err| StorageError::DatabaseError(err.to_string()))?;
            rows.map(|row| {
                let payload = row.map_err(|err| StorageError::DatabaseError(err.to_string()))?;
                serde_json::from_str(&payload).map_err(StorageError::from)
            })
            .collect()
        })
        .await
    }

    async fn save_containment_command(
        &self,
        command: &SignedContainmentCommand,
    ) -> Result<(), StorageError> {
        let command = command.clone();
        self.run_blocking(move |connection| {
            let payload = serde_json::to_string(&command)?;
            let status = enum_string(&command.status)?;
            connection
                .execute(
                    "INSERT INTO containment_commands
                     (command_id, action, target_entity, status, issued_at, payload_json)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(command_id) DO UPDATE SET
                        status = excluded.status,
                        payload_json = excluded.payload_json",
                    params![
                        command.command_id.to_string(),
                        command.action.as_str(),
                        command.target_entity,
                        status,
                        command.issued_at.to_rfc3339(),
                        payload,
                    ],
                )
                .map_err(|err| StorageError::DatabaseError(err.to_string()))?;
            Ok(())
        })
        .await
    }

    async fn get_containment_commands(
        &self,
    ) -> Result<Vec<SignedContainmentCommand>, StorageError> {
        self.run_blocking(move |connection| {
            let mut statement = connection
                .prepare("SELECT payload_json FROM containment_commands ORDER BY issued_at DESC")
                .map_err(|err| StorageError::DatabaseError(err.to_string()))?;
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(|err| StorageError::DatabaseError(err.to_string()))?;
            rows.map(|row| {
                let payload = row.map_err(|err| StorageError::DatabaseError(err.to_string()))?;
                serde_json::from_str(&payload).map_err(StorageError::from)
            })
            .collect()
        })
        .await
    }
}

fn enum_string<T: serde::Serialize>(value: &T) -> Result<String, StorageError> {
    serde_json::to_value(value)?
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| StorageError::DatabaseError("expected enum to serialize as a string".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use security_control_plane_common::{
        ControlPlaneKeypair, SensorMetadata, SensorType, Severity, SourceContext,
    };
    use uuid::Uuid;

    fn event() -> SecurityEvent {
        let mut event = SecurityEvent::new(
            "test-app",
            "test",
            "auth.login",
            SourceContext {
                ip: Some("192.0.2.10".into()),
                port: Some(443),
                user_agent: None,
                sensor: SensorMetadata {
                    sensor_type: SensorType::Agent,
                    raw_event_type: "http_request".into(),
                    sensor_id: None,
                    raw_payload: None,
                },
                container_id: None,
                pid: None,
                process_name: None,
            },
        );
        event.severity = Severity::High;
        event.is_security_significant = true;
        event
    }

    #[tokio::test]
    async fn saves_and_reads_security_events() {
        let sink = SqliteDurableSink::in_memory().expect("in-memory database");
        let event = event();
        assert_eq!(
            sink.save_batch(&[event.clone()]).await.expect("save event"),
            1
        );
        let events = sink.get_recent_events(10).await.expect("read events");
        assert_eq!(events, vec![event]);
    }

    #[tokio::test]
    async fn saves_and_reads_incidents() {
        let sink = SqliteDurableSink::in_memory().expect("in-memory database");
        let event = event();
        let signal = security_control_plane_engine::SecuritySignal {
            signal_id: Uuid::new_v4(),
            rule_name: "test-rule".into(),
            severity: Severity::High,
            description: "test incident".into(),
            risk_weight: 40,
            timestamp: Utc::now(),
            matched_event_ids: vec![event.event_id],
        };
        let incident = Incident::new(
            "test incident",
            "description",
            Severity::High,
            "ip:192.0.2.10",
            "test-app",
            signal,
            event,
        );

        sink.save_incident(&incident).await.expect("save incident");
        let incidents = sink.get_incidents().await.expect("read incidents");
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].incident_id, incident.incident_id);
    }

    #[tokio::test]
    async fn saves_and_reads_containment_audit_records() {
        let sink = SqliteDurableSink::in_memory().expect("in-memory database");
        let keypair = ControlPlaneKeypair::generate();
        let mut command = SignedContainmentCommand::new(
            security_control_plane_common::ContainmentActionType::BlockNetwork,
            "ip:192.0.2.10",
            None,
            Default::default(),
            30,
            None,
            "remove block",
        );
        command.sign(&keypair);
        sink.save_containment_command(&command)
            .await
            .expect("save command");
        assert_eq!(
            sink.get_containment_commands()
                .await
                .expect("read commands")[0]
                .command_id,
            command.command_id
        );
    }
}
