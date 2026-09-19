use crate::incident::SecuritySignal;
use crate::state::{HotStateError, HotStateStore};
use async_trait::async_trait;
use chrono::Utc;
use security_control_plane_common::{SecurityEvent, SensorType, Severity};
use uuid::Uuid;

#[async_trait]
pub trait Rule: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn default_severity(&self) -> Severity;
    fn base_risk_weight(&self) -> u32;

    async fn evaluate(
        &self,
        event: &SecurityEvent,
        state: &dyn HotStateStore,
    ) -> Result<Option<SecuritySignal>, HotStateError>;
}

// =========================================================================
// 1. Brute-Force & Credential Stuffing Rule
// =========================================================================
pub struct BruteForceRule {
    pub window_ms: i64,
    pub threshold: u64,
}

impl Default for BruteForceRule {
    fn default() -> Self {
        Self {
            window_ms: 60_000, // 60 seconds
            threshold: 10,     // 10 failed logins
        }
    }
}

#[async_trait]
impl Rule for BruteForceRule {
    fn id(&self) -> &'static str {
        "RULE_BRUTE_FORCE"
    }

    fn name(&self) -> &'static str {
        "Credential Brute-Force / Password Spray"
    }

    fn description(&self) -> &'static str {
        "Detects high-frequency authentication failures indicative of brute-force or credential stuffing."
    }

    fn default_severity(&self) -> Severity {
        Severity::High
    }

    fn base_risk_weight(&self) -> u32 {
        35
    }

    async fn evaluate(
        &self,
        event: &SecurityEvent,
        state: &dyn HotStateStore,
    ) -> Result<Option<SecuritySignal>, HotStateError> {
        let is_auth_failure = event
            .action
            .as_ref()
            .map(|a| {
                !a.is_success
                    && (a.status_code == Some(401)
                        || a.endpoint
                            .as_deref()
                            .map_or(false, |ep| ep.contains("login") || ep.contains("auth") || ep.contains("token") || ep.contains("session")))
            })
            .unwrap_or(false);

        if !is_auth_failure {
            return Ok(None);
        }

        let ip = event.source.ip.as_deref().unwrap_or("unknown");
        let key = format!("bf:ip:{}", ip);
        let ts = event.timestamp.timestamp_millis();

        let count = state.record_hit(&key, ts, self.window_ms).await?;

        if count >= self.threshold {
            Ok(Some(SecuritySignal {
                signal_id: Uuid::new_v4(),
                rule_name: self.name().to_string(),
                severity: self.default_severity(),
                description: format!(
                    "Detected credential brute-force attack from IP {}: {} failed authentication attempts within {}s",
                    ip,
                    count,
                    self.window_ms / 1000
                ),
                risk_weight: self.base_risk_weight(),
                timestamp: Utc::now(),
                matched_event_ids: vec![event.event_id],
            }))
        } else {
            Ok(None)
        }
    }
}

// =========================================================================
// 2. Rapid API / Directory Enumeration Rule
// =========================================================================
pub struct RapidApiEnumerationRule {
    pub window_ms: i64,
    pub count_threshold: u64,
    pub distinct_threshold: u64,
}

impl Default for RapidApiEnumerationRule {
    fn default() -> Self {
        Self {
            window_ms: 60_000,
            count_threshold: 20,
            distinct_threshold: 25,
        }
    }
}

#[async_trait]
impl Rule for RapidApiEnumerationRule {
    fn id(&self) -> &'static str {
        "RULE_API_ENUMERATION"
    }

    fn name(&self) -> &'static str {
        "Rapid API / Directory Enumeration Scan"
    }

    fn description(&self) -> &'static str {
        "Detects automated directory busting, endpoint fuzzing, and reconnaissance via rapid 404 responses."
    }

    fn default_severity(&self) -> Severity {
        Severity::Medium
    }

    fn base_risk_weight(&self) -> u32 {
        25
    }

    async fn evaluate(
        &self,
        event: &SecurityEvent,
        state: &dyn HotStateStore,
    ) -> Result<Option<SecuritySignal>, HotStateError> {
        let is_404 = event
            .action
            .as_ref()
            .and_then(|a| a.status_code)
            .map(|sc| sc == 404)
            .unwrap_or(false);

        if !is_404 {
            return Ok(None);
        }

        let ip = event.source.ip.as_deref().unwrap_or("unknown");
        let key_404 = format!("enum_404:ip:{}", ip);
        let ts = event.timestamp.timestamp_millis();
        let count_404 = state.record_hit(&key_404, ts, self.window_ms).await?;

        let route = event
            .action
            .as_ref()
            .and_then(|a| a.endpoint.as_deref())
            .unwrap_or("unknown_route");
        let set_key = format!("enum_paths:ip:{}", ip);
        let distinct_count = state
            .record_distinct(&set_key, route, (self.window_ms / 1000) as u64)
            .await?;

        if count_404 >= self.count_threshold || distinct_count >= self.distinct_threshold {
            Ok(Some(SecuritySignal {
                signal_id: Uuid::new_v4(),
                rule_name: self.name().to_string(),
                severity: self.default_severity(),
                description: format!(
                    "Detected rapid API enumeration from IP {}: {} 404 errors across {} distinct endpoints in {}s",
                    ip,
                    count_404,
                    distinct_count,
                    self.window_ms / 1000
                ),
                risk_weight: self.base_risk_weight(),
                timestamp: Utc::now(),
                matched_event_ids: vec![event.event_id],
            }))
        } else {
            Ok(None)
        }
    }
}

// =========================================================================
// 3. Unauthorized Access Burst (401 / 403) Rule
// =========================================================================
pub struct UnauthorizedBurstRule {
    pub window_ms: i64,
    pub threshold: u64,
}

impl Default for UnauthorizedBurstRule {
    fn default() -> Self {
        Self {
            window_ms: 60_000,
            threshold: 15,
        }
    }
}

#[async_trait]
impl Rule for UnauthorizedBurstRule {
    fn id(&self) -> &'static str {
        "RULE_UNAUTHORIZED_BURST"
    }

    fn name(&self) -> &'static str {
        "Unauthorized Access Burst (401/403)"
    }

    fn description(&self) -> &'static str {
        "Detects abnormal surges in unauthorized or forbidden responses indicating privilege probing or token forgery."
    }

    fn default_severity(&self) -> Severity {
        Severity::High
    }

    fn base_risk_weight(&self) -> u32 {
        30
    }

    async fn evaluate(
        &self,
        event: &SecurityEvent,
        state: &dyn HotStateStore,
    ) -> Result<Option<SecuritySignal>, HotStateError> {
        let is_unauthorized = event
            .action
            .as_ref()
            .and_then(|a| a.status_code)
            .map(|sc| sc == 401 || sc == 403)
            .unwrap_or(false);

        if !is_unauthorized {
            return Ok(None);
        }

        let ip = event.source.ip.as_deref().unwrap_or("unknown");
        let key = format!("unauth:ip:{}", ip);
        let ts = event.timestamp.timestamp_millis();

        let count = state.record_hit(&key, ts, self.window_ms).await?;

        if count >= self.threshold {
            Ok(Some(SecuritySignal {
                signal_id: Uuid::new_v4(),
                rule_name: self.name().to_string(),
                severity: self.default_severity(),
                description: format!(
                    "Detected abnormal burst of unauthorized (401/403) requests from IP {}: {} occurrences within {}s",
                    ip,
                    count,
                    self.window_ms / 1000
                ),
                risk_weight: self.base_risk_weight(),
                timestamp: Utc::now(),
                matched_event_ids: vec![event.event_id],
            }))
        } else {
            Ok(None)
        }
    }
}

// =========================================================================
// 4. Mass Data Scraping / Atypical Export Rule
// =========================================================================
pub struct MassDataScrapingRule {
    pub window_ms: i64,
    pub threshold: u64,
}

impl Default for MassDataScrapingRule {
    fn default() -> Self {
        Self {
            window_ms: 60_000,
            threshold: 25,
        }
    }
}

#[async_trait]
impl Rule for MassDataScrapingRule {
    fn id(&self) -> &'static str {
        "RULE_MASS_DATA_SCRAPING"
    }

    fn name(&self) -> &'static str {
        "Mass Data Scraping / Export Burst"
    }

    fn description(&self) -> &'static str {
        "Detects high-volume, rapid extraction of database records or sensitive data endpoints."
    }

    fn default_severity(&self) -> Severity {
        Severity::High
    }

    fn base_risk_weight(&self) -> u32 {
        30
    }

    async fn evaluate(
        &self,
        event: &SecurityEvent,
        state: &dyn HotStateStore,
    ) -> Result<Option<SecuritySignal>, HotStateError> {
        let is_data_endpoint = event
            .action
            .as_ref()
            .map(|a| {
                let ep = a.endpoint.as_deref().unwrap_or("");
                let method = a.method.as_deref().unwrap_or("");
                method == "GET"
                    && (ep.contains("/export")
                        || ep.contains("/records")
                        || ep.contains("/download")
                        || ep.contains("/customers")
                        || ep.contains("/dump"))
            })
            .unwrap_or(false);

        if !is_data_endpoint {
            return Ok(None);
        }

        let ip = event.source.ip.as_deref().unwrap_or("unknown");
        let key = format!("scrape:ip:{}", ip);
        let ts = event.timestamp.timestamp_millis();

        let count = state.record_hit(&key, ts, self.window_ms).await?;

        if count >= self.threshold {
            Ok(Some(SecuritySignal {
                signal_id: Uuid::new_v4(),
                rule_name: self.name().to_string(),
                severity: self.default_severity(),
                description: format!(
                    "Detected mass data scraping from IP {}: {} data query requests in {}s",
                    ip,
                    count,
                    self.window_ms / 1000
                ),
                risk_weight: self.base_risk_weight(),
                timestamp: Utc::now(),
                matched_event_ids: vec![event.event_id],
            }))
        } else {
            Ok(None)
        }
    }
}

// =========================================================================
// 5. Kernel & Runtime Container Anomaly Rule (Tetragon / Falco eBPF)
// =========================================================================
pub struct KernelAnomalyRule;

#[async_trait]
impl Rule for KernelAnomalyRule {
    fn id(&self) -> &'static str {
        "RULE_KERNEL_ANOMALY"
    }

    fn name(&self) -> &'static str {
        "Suspicious Container / Kernel Execution"
    }

    fn description(&self) -> &'static str {
        "Detects interactive shells, unapproved utilities, or privilege escalations in containers captured via eBPF."
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn base_risk_weight(&self) -> u32 {
        50
    }

    async fn evaluate(
        &self,
        event: &SecurityEvent,
        _state: &dyn HotStateStore,
    ) -> Result<Option<SecuritySignal>, HotStateError> {
        let is_kernel_sensor = matches!(
            event.source.sensor.sensor_type,
            SensorType::Tetragon | SensorType::Falco | SensorType::System
        ) || event.event_type.contains("process_exec")
            || event.event_type.contains("falco")
            || event.event_type.contains("tetragon");

        let suspicious_binaries = [
            "/bin/sh",
            "/bin/bash",
            "sh",
            "bash",
            "nc",
            "ncat",
            "netcat",
            "curl",
            "wget",
            "socat",
            "sudo",
        ];

        let proc_name = event.source.process_name.as_deref().unwrap_or("");
        let endpoint_or_cmd = event
            .action
            .as_ref()
            .and_then(|a| a.endpoint.as_deref())
            .unwrap_or("");
        let raw_type = &event.source.sensor.raw_event_type;

        let matches_binary = suspicious_binaries.iter().any(|&b| {
            proc_name.ends_with(b)
                || endpoint_or_cmd.contains(b)
                || raw_type.contains(b)
        });

        if is_kernel_sensor && (matches_binary || event.severity == Severity::Critical) {
            Ok(Some(SecuritySignal {
                signal_id: Uuid::new_v4(),
                rule_name: self.name().to_string(),
                severity: Severity::Critical,
                description: format!(
                    "Kernel/eBPF runtime alarm: unauthorized binary or shell execution detected in app container '{}' (binary: '{}', sensor: {:?})",
                    event.app_id,
                    if !proc_name.is_empty() { proc_name } else { endpoint_or_cmd },
                    event.source.sensor.sensor_type
                ),
                risk_weight: self.base_risk_weight(),
                timestamp: Utc::now(),
                matched_event_ids: vec![event.event_id],
            }))
        } else {
            Ok(None)
        }
    }
}

// =========================================================================
// 6. Privilege Creep Rule (Admin Route Access Without Admin Role)
// =========================================================================
pub struct PrivilegeCreepRule;

#[async_trait]
impl Rule for PrivilegeCreepRule {
    fn id(&self) -> &'static str {
        "RULE_PRIVILEGE_CREEP"
    }

    fn name(&self) -> &'static str {
        "Administrative Privilege Creep / Probe"
    }

    fn description(&self) -> &'static str {
        "Detects unprivileged users or unauthenticated clients attempting to access sensitive administrative routes."
    }

    fn default_severity(&self) -> Severity {
        Severity::High
    }

    fn base_risk_weight(&self) -> u32 {
        35
    }

    async fn evaluate(
        &self,
        event: &SecurityEvent,
        _state: &dyn HotStateStore,
    ) -> Result<Option<SecuritySignal>, HotStateError> {
        let is_admin_route = event
            .action
            .as_ref()
            .and_then(|a| a.endpoint.as_deref())
            .map(|ep| ep.contains("/admin") || ep.contains("/root") || ep.contains("/system/keys"))
            .unwrap_or(false);

        if !is_admin_route {
            return Ok(None);
        }

        let is_not_admin = event
            .actor
            .as_ref()
            .and_then(|act| act.role.as_deref())
            .map(|role| role != "admin")
            .unwrap_or(true); // default to true if unauthenticated

        let status_code = event
            .action
            .as_ref()
            .and_then(|a| a.status_code)
            .unwrap_or(200);

        if is_not_admin && (status_code == 401 || status_code == 403 || status_code == 200) {
            let user = event
                .actor
                .as_ref()
                .and_then(|a| a.user_id.as_deref())
                .unwrap_or("unauthenticated");
            let ip = event.source.ip.as_deref().unwrap_or("unknown");

            Ok(Some(SecuritySignal {
                signal_id: Uuid::new_v4(),
                rule_name: self.name().to_string(),
                severity: self.default_severity(),
                description: format!(
                    "Unauthorized actor '{}' from IP {} probed sensitive admin endpoint (status: {})",
                    user, ip, status_code
                ),
                risk_weight: self.base_risk_weight(),
                timestamp: Utc::now(),
                matched_event_ids: vec![event.event_id],
            }))
        } else {
            Ok(None)
        }
    }
}
