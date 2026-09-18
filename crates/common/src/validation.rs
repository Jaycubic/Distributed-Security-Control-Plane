use crate::models::SecurityEvent;
use chrono::{Duration, Utc};
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum ValidationError {
    #[error("Missing or empty field: {0}")]
    MissingField(&'static str),

    #[error("Field exceeds maximum length: {field} (max {max}, got {actual})")]
    FieldTooLong {
        field: &'static str,
        max: usize,
        actual: usize,
    },

    #[error("Timestamp skew error: {0}")]
    TimestampSkew(String),

    #[error("Oversized event payload: exceeds {0} bytes")]
    PayloadTooLarge(usize),
}

pub const MAX_EVENT_SIZE_BYTES: usize = 65_536; // 64 KB
pub const MAX_ID_LENGTH: usize = 128;
pub const MAX_FUTURE_SKEW_SECONDS: i64 = 3600; // 1 hour
pub const MAX_PAST_SKEW_SECONDS: i64 = 7 * 86400; // 7 days

pub fn validate_security_event(event: &SecurityEvent) -> Result<(), ValidationError> {
    if event.app_id.trim().is_empty() {
        return Err(ValidationError::MissingField("app_id"));
    }
    if event.app_id.len() > MAX_ID_LENGTH {
        return Err(ValidationError::FieldTooLong {
            field: "app_id",
            max: MAX_ID_LENGTH,
            actual: event.app_id.len(),
        });
    }

    if event.environment.trim().is_empty() {
        return Err(ValidationError::MissingField("environment"));
    }

    if event.event_type.trim().is_empty() {
        return Err(ValidationError::MissingField("event_type"));
    }
    if event.event_type.len() > MAX_ID_LENGTH {
        return Err(ValidationError::FieldTooLong {
            field: "event_type",
            max: MAX_ID_LENGTH,
            actual: event.event_type.len(),
        });
    }

    if event.source.sensor.raw_event_type.trim().is_empty() {
        return Err(ValidationError::MissingField("source.sensor.raw_event_type"));
    }

    // Timestamp skew validation
    let now = Utc::now();
    let future_limit = now + Duration::seconds(MAX_FUTURE_SKEW_SECONDS);
    let past_limit = now - Duration::seconds(MAX_PAST_SKEW_SECONDS);

    if event.timestamp > future_limit {
        return Err(ValidationError::TimestampSkew(format!(
            "Timestamp is too far in the future: {}",
            event.timestamp
        )));
    }
    if event.timestamp < past_limit {
        return Err(ValidationError::TimestampSkew(format!(
            "Timestamp is too far in the past: {}",
            event.timestamp
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{SensorMetadata, SensorType, SourceContext};

    fn sample_event() -> SecurityEvent {
        SecurityEvent::new(
            "test-app",
            "production",
            "http.request",
            SourceContext {
                ip: Some("127.0.0.1".into()),
                port: Some(8080),
                user_agent: Some("TestAgent/1.0".into()),
                sensor: SensorMetadata {
                    sensor_type: SensorType::Agent,
                    raw_event_type: "http_inbound".into(),
                    sensor_id: None,
                    raw_payload: None,
                },
                container_id: None,
                pid: None,
                process_name: None,
            },
        )
    }

    #[test]
    fn test_valid_event() {
        let event = sample_event();
        assert!(validate_security_event(&event).is_ok());
    }

    #[test]
    fn test_empty_app_id() {
        let mut event = sample_event();
        event.app_id = "   ".into();
        assert_eq!(
            validate_security_event(&event),
            Err(ValidationError::MissingField("app_id"))
        );
    }

    #[test]
    fn test_future_skew() {
        let mut event = sample_event();
        event.timestamp = Utc::now() + Duration::hours(3);
        assert!(matches!(
            validate_security_event(&event),
            Err(ValidationError::TimestampSkew(_))
        ));
    }
}
