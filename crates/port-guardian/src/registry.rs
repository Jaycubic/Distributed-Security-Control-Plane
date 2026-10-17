use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;

const DEFAULT_BINDING_TTL_HOURS: i64 = 24;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortBinding {
    pub port: u16,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub bound_at: DateTime<Utc>,
    pub is_active: bool,
}

#[derive(Default)]
pub struct PortRegistry {
    bindings: RwLock<HashMap<u16, PortBinding>>,
}

impl PortRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn record_binding(&self, binding: PortBinding) {
        self.bindings.write().await.insert(binding.port, binding);
    }

    pub async fn is_registered(&self, port: u16) -> bool {
        let mut bindings = self.bindings.write().await;
        evict_expired(&mut bindings);
        bindings
            .get(&port)
            .map(|binding| binding.is_active)
            .unwrap_or(false)
    }

    pub async fn get_bindings(&self) -> Result<Vec<PortBinding>, std::convert::Infallible> {
        let mut bindings = self.bindings.write().await;
        evict_expired(&mut bindings);
        let mut result: Vec<_> = bindings.values().cloned().collect();
        result.sort_by_key(|binding| binding.port);
        Ok(result)
    }
}

fn evict_expired(bindings: &mut HashMap<u16, PortBinding>) {
    let cutoff = Utc::now() - Duration::hours(DEFAULT_BINDING_TTL_HOURS);
    bindings.retain(|_, binding| binding.is_active && binding.bound_at >= cutoff);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn records_binding_and_replaces_duplicate_port() {
        let registry = PortRegistry::new();
        let now = Utc::now();
        registry
            .record_binding(PortBinding {
                port: 8080,
                pid: Some(1000),
                process_name: Some("nginx".into()),
                bound_at: now,
                is_active: true,
            })
            .await;
        registry
            .record_binding(PortBinding {
                port: 8080,
                pid: Some(2000),
                process_name: Some("caddy".into()),
                bound_at: now,
                is_active: true,
            })
            .await;

        let bindings = registry.get_bindings().await.expect("registry read");
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].pid, Some(2000));
        assert_eq!(bindings[0].process_name.as_deref(), Some("caddy"));
    }

    #[tokio::test]
    async fn evicts_expired_binding() {
        let registry = PortRegistry::new();
        registry
            .record_binding(PortBinding {
                port: 8080,
                pid: Some(1000),
                process_name: None,
                bound_at: Utc::now() - Duration::hours(DEFAULT_BINDING_TTL_HOURS + 1),
                is_active: true,
            })
            .await;

        assert!(!registry.is_registered(8080).await);
        assert!(registry
            .get_bindings()
            .await
            .expect("registry read")
            .is_empty());
    }
}
