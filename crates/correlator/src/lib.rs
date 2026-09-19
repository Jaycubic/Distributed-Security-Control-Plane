pub mod capability;
pub mod graph;
pub mod identity;
pub mod sequence;

pub use capability::{infer_capabilities, CapabilityType};
pub use graph::{GraphEdge, GraphNode, MemoryContextGraph, NodeCategory, SubGraph};
pub use identity::{CanonicalEntity, EntityType, IdentityResolver};
pub use sequence::{AttackStage, CrossAppSequenceDetector, EntityAttackProgress, StageObservation};

use security_control_plane_common::SecurityEvent;
use security_control_plane_engine::SecuritySignal;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Unified Correlation Engine tying together Identity Resolution,
/// In-Memory Relationship Graph, Capability Context, and Cross-App Sequence Detection.
pub struct CorrelationEngine {
    identity: Arc<RwLock<IdentityResolver>>,
    graph: Arc<RwLock<MemoryContextGraph>>,
    sequence_detector: Arc<RwLock<CrossAppSequenceDetector>>,
}

impl Default for CorrelationEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl CorrelationEngine {
    pub fn new() -> Self {
        Self {
            identity: Arc::new(RwLock::new(IdentityResolver::new())),
            graph: Arc::new(RwLock::new(MemoryContextGraph::new(3600))),
            sequence_detector: Arc::new(RwLock::new(CrossAppSequenceDetector::new(600))),
        }
    }

    /// Process an ingested security event through the correlation pipeline:
    /// 1. Resolve canonical identity and link aliases.
    /// 2. Infer exercised capabilities (Deno-inspired capability context).
    /// 3. Update the in-memory relationship graph.
    /// 4. Evaluate multi-stage cross-application attack progression.
    /// Returns the resolved canonical entity_id and any detected cross-app signal.
    pub async fn process_event(
        &self,
        event: &SecurityEvent,
    ) -> (String, Option<SecuritySignal>) {
        // 1. Resolve identity
        let canonical_id = {
            let mut id_lock = self.identity.write().await;
            id_lock.resolve_and_update(event)
        };

        // 2. Infer capabilities
        let capabilities = infer_capabilities(event);

        // Update exercised capabilities on the canonical entity
        {
            let mut id_lock = self.identity.write().await;
            if let Some(entity) = id_lock.get_mut(&canonical_id) {
                for cap in &capabilities {
                    entity.exercised_capabilities.insert(cap.as_str().to_string());
                }
            }
        }

        // 3. Update context graph
        {
            let mut graph_lock = self.graph.write().await;
            graph_lock.record_event(event, &canonical_id, &capabilities);
        }

        // 4. Evaluate cross-application attack progression
        let signal = {
            let mut seq_lock = self.sequence_detector.write().await;
            seq_lock.evaluate_event(event, &canonical_id, &capabilities)
        };

        (canonical_id, signal)
    }

    pub fn identity_resolver(&self) -> Arc<RwLock<IdentityResolver>> {
        self.identity.clone()
    }

    pub fn context_graph(&self) -> Arc<RwLock<MemoryContextGraph>> {
        self.graph.clone()
    }

    pub fn sequence_detector(&self) -> Arc<RwLock<CrossAppSequenceDetector>> {
        self.sequence_detector.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use security_control_plane_common::{
        ActionContext, ActorContext, SecurityEvent, SensorMetadata, SensorType, Severity,
        SourceContext,
    };
    use uuid::Uuid;

    fn make_test_event(
        app_id: &str,
        ip: &str,
        session_id: Option<&str>,
        user_id: Option<&str>,
        endpoint: &str,
        is_success: bool,
        status_code: u16,
    ) -> SecurityEvent {
        SecurityEvent {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            app_id: app_id.to_string(),
            environment: "test".to_string(),
            event_type: "http_request".to_string(),
            severity: if is_success { Severity::Low } else { Severity::Medium },
            actor: Some(ActorContext {
                user_id: user_id.map(|s| s.to_string()),
                role: None,
                session_id: session_id.map(|s| s.to_string()),
                auth_method: None,
                client_fingerprint: None,
            }),
            source: SourceContext {
                ip: Some(ip.to_string()),
                port: Some(12345),
                user_agent: Some("TestAgent/1.0".to_string()),
                sensor: SensorMetadata {
                    sensor_type: SensorType::Agent,
                    raw_event_type: "http".to_string(),
                    sensor_id: None,
                    raw_payload: None,
                },
                container_id: None,
                pid: None,
                process_name: None,
            },
            action: Some(ActionContext {
                method: Some("GET".to_string()),
                endpoint: Some(endpoint.to_string()),
                status_code: Some(status_code),
                duration_us: Some(100),
                is_success,
                operation: None,
            }),
            resource: None,
            metadata: Default::default(),
            is_security_significant: !is_success,
        }
    }

    #[tokio::test]
    async fn test_identity_resolution_and_alias_merging() {
        let engine = CorrelationEngine::new();

        // 1. Event from IP only
        let ev1 = make_test_event("app-a", "198.51.100.5", None, None, "/home", true, 200);
        let (id1, _) = engine.process_event(&ev1).await;
        assert_eq!(id1, "canonical:ip:198.51.100.5");

        // 2. Same IP logs in with session sess_abc
        let ev2 = make_test_event(
            "app-a",
            "198.51.100.5",
            Some("sess_abc"),
            None,
            "/login",
            true,
            200,
        );
        let (id2, _) = engine.process_event(&ev2).await;
        // Linked to existing IP entity
        assert_eq!(id2, "canonical:ip:198.51.100.5");

        // 3. User alice uses session sess_abc on app-b from different IP
        let ev3 = make_test_event(
            "app-b",
            "203.0.113.88",
            Some("sess_abc"),
            Some("alice"),
            "/profile",
            true,
            200,
        );
        let (id3, _) = engine.process_event(&ev3).await;
        // User identity should become canonical and merge prior IP
        let id_resolver = engine.identity_resolver();
        let lock = id_resolver.read().await;
        let entity = lock.get(&id3).expect("Entity should exist");
        assert!(entity.linked_ips.contains("198.51.100.5"));
        assert!(entity.linked_ips.contains("203.0.113.88"));
        assert!(entity.linked_sessions.contains("sess_abc"));
        assert!(entity.linked_user_ids.contains("alice"));
        assert!(entity.apps_seen.contains("app-a"));
        assert!(entity.apps_seen.contains("app-b"));
    }

    #[tokio::test]
    async fn test_context_graph_and_subgraph() {
        let engine = CorrelationEngine::new();
        let ev = make_test_event(
            "billing-service",
            "192.0.2.1",
            Some("sess_999"),
            Some("bob"),
            "/invoices/export",
            true,
            200,
        );
        let (id, _) = engine.process_event(&ev).await;

        let graph = engine.context_graph();
        let lock = graph.read().await;
        let sub = lock.get_subgraph(&id);
        assert!(!sub.nodes.is_empty());
        assert!(!sub.edges.is_empty());

        let categories: Vec<NodeCategory> = sub.nodes.iter().map(|n| n.category.clone()).collect();
        assert!(categories.contains(&NodeCategory::Entity));
        assert!(categories.contains(&NodeCategory::Application));
        assert!(categories.contains(&NodeCategory::Endpoint));
    }

    #[tokio::test]
    async fn test_cross_app_attack_sequence_detection() {
        let engine = CorrelationEngine::new();

        // Stage 1: Recon on App A (Reconnaissance via 404 probes)
        let ev1 = make_test_event(
            "billing-app",
            "198.51.100.99",
            Some("sess_attacker"),
            None,
            "/admin/debug",
            false,
            404,
        );
        let (id1, sig1) = engine.process_event(&ev1).await;
        assert!(sig1.is_none());

        // Stage 2: Lateral transition to App B with active session
        let ev2 = make_test_event(
            "auth-portal",
            "198.51.100.99",
            Some("sess_attacker"),
            Some("infiltrator"),
            "/api/v1/users",
            true,
            200,
        );
        let (id2, sig2) = engine.process_event(&ev2).await;
        assert_eq!(id1, id2);
        assert!(sig2.is_none());

        // Stage 3: High-impact mass export on App C
        let ev3 = make_test_event(
            "crm-service",
            "198.51.100.99",
            Some("sess_attacker"),
            Some("infiltrator"),
            "/api/v1/customers/export",
            true,
            200,
        );
        let (_, sig3) = engine.process_event(&ev3).await;

        // Multi-Stage Cross-App Attack Chain should be detected!
        assert!(sig3.is_some(), "Expected cross-application attack chain signal to fire");
        let signal = sig3.unwrap();
        assert_eq!(signal.rule_name, "Multi-Stage Cross-Application Attack Chain");
        assert_eq!(signal.severity, Severity::Critical);
        assert_eq!(signal.risk_weight, 75);
        assert!(signal.description.contains("billing-app"));
        assert!(signal.description.contains("crm-service"));
    }
}
