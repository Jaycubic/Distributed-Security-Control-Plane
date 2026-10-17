use crate::PortGuardianError;
use security_control_plane_engine::HotStateStore;
use std::sync::Arc;

pub struct PortScanDetector {
    hot_state: Arc<dyn HotStateStore>,
    window_ms: i64,
    distinct_port_threshold: u64,
    connection_rate_threshold: u64,
}

impl PortScanDetector {
    pub fn new(hot_state: Arc<dyn HotStateStore>) -> Self {
        Self::with_thresholds(hot_state, 10_000, 15, 50)
    }

    pub fn with_thresholds(
        hot_state: Arc<dyn HotStateStore>,
        window_ms: i64,
        distinct_port_threshold: u64,
        connection_rate_threshold: u64,
    ) -> Self {
        Self {
            hot_state,
            window_ms,
            distinct_port_threshold,
            connection_rate_threshold,
        }
    }

    pub async fn observe(
        &self,
        source_ip: &str,
        destination_port: u16,
        timestamp_ms: i64,
    ) -> Result<Option<String>, PortGuardianError> {
        let distinct_key = format!("portscan:distinct_ports:ip:{source_ip}");
        let distinct_count = self
            .hot_state
            .record_distinct(
                &distinct_key,
                &destination_port.to_string(),
                (self.window_ms / 1000).max(1) as u64,
            )
            .await?;

        let rate_key = format!("portscan:conn_rate:ip:{source_ip}");
        let connection_count = self
            .hot_state
            .record_hit(&rate_key, timestamp_ms, self.window_ms)
            .await?;

        if distinct_count >= self.distinct_port_threshold {
            return Ok(Some(format!(
                "Port scan detected from {source_ip}: probed {distinct_count} registered ports within {}s",
                self.window_ms / 1000
            )));
        }
        if connection_count >= self.connection_rate_threshold {
            return Ok(Some(format!(
                "Connection flood from {source_ip}: {connection_count} connections to registered ports within {}s",
                self.window_ms / 1000
            )));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use security_control_plane_engine::MemoryHotState;

    #[tokio::test]
    async fn detects_distinct_registered_port_probes() {
        let detector =
            PortScanDetector::with_thresholds(Arc::new(MemoryHotState::new()), 10_000, 15, 50);
        let mut result = None;
        for port in 1..=15 {
            result = detector
                .observe("192.0.2.5", port, 1_000 + i64::from(port))
                .await
                .unwrap();
        }
        assert!(result.unwrap().contains("Port scan detected"));
    }

    #[tokio::test]
    async fn detects_connection_flood() {
        let detector =
            PortScanDetector::with_thresholds(Arc::new(MemoryHotState::new()), 10_000, 100, 50);
        let mut result = None;
        for index in 0..50 {
            result = detector
                .observe("192.0.2.6", 8080, 1_000 + index)
                .await
                .unwrap();
        }
        assert!(result.unwrap().contains("Connection flood"));
    }
}
