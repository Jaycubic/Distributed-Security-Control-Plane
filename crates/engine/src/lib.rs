pub mod advisory;
pub mod containment;
pub mod evaluator;
pub mod incident;
pub mod policy;
pub mod rules;
pub mod state;

pub use advisory::{AdvisoryManager, AdvisoryPolicyGate};
pub use containment::{ContainmentError, ContainmentManager};
pub use evaluator::RuleEngine;
pub use incident::{Incident, IncidentStatus, SecuritySignal};
pub use policy::CapabilityPolicyEngine;
pub use rules::{
    BruteForceRule, KernelAnomalyRule, MassDataScrapingRule, PrivilegeCreepRule,
    RapidApiEnumerationRule, Rule, UnauthorizedBurstRule,
};
pub use state::{HotStateError, HotStateStore, MemoryHotState, RedisHotState};

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use security_control_plane_common::{
        ActionContext, ActorContext, SecurityEvent, SensorMetadata, SensorType, SourceContext,
        Severity,
    };
    use std::collections::HashMap;
    use std::sync::Arc;
    use uuid::Uuid;

    fn mock_login_event(ip: &str, is_success: bool) -> SecurityEvent {
        SecurityEvent {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            app_id: "test-app".into(),
            environment: "test".into(),
            event_type: "auth.login".into(),
            severity: if is_success { Severity::Low } else { Severity::Medium },
            actor: Some(ActorContext {
                user_id: Some("attacker".into()),
                role: None,
                session_id: None,
                auth_method: Some("password".into()),
                client_fingerprint: None,
            }),
            source: SourceContext {
                ip: Some(ip.into()),
                port: Some(54321),
                user_agent: Some("TestHarness/1.0".into()),
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
            action: Some(ActionContext {
                method: Some("POST".into()),
                endpoint: Some("/api/v1/auth/login".into()),
                status_code: Some(if is_success { 200 } else { 401 }),
                duration_us: Some(150),
                is_success,
                operation: Some("login".into()),
            }),
            resource: None,
            metadata: std::collections::HashMap::new(),
            is_security_significant: !is_success,
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_memory_hot_state_sliding_window() {
        let state = MemoryHotState::new();
        let now = Utc::now().timestamp_millis();
        let key = "test:counter";

        // Record 5 events 100ms apart
        for i in 0..5 {
            let count = state.record_hit(key, now + (i * 100), 1000).await.unwrap();
            assert_eq!(count, (i + 1) as u64);
        }

        // Count inside 1000ms window
        let window_count = state.count_in_window(key, 1000, now + 400).await.unwrap();
        assert_eq!(window_count, 5);

        // Distinct set test
        let set_key = "test:distinct";
        assert_eq!(state.record_distinct(set_key, "/a", 10).await.unwrap(), 1);
        assert_eq!(state.record_distinct(set_key, "/b", 10).await.unwrap(), 2);
        assert_eq!(state.record_distinct(set_key, "/a", 10).await.unwrap(), 2);
        assert_eq!(state.count_distinct(set_key).await.unwrap(), 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_brute_force_detection_and_incident_escalation() {
        let state = Arc::new(MemoryHotState::new());
        let engine = RuleEngine::with_default_rules(state);

        // Send 9 failed logins (threshold is 10)
        for _ in 0..9 {
            let ev = mock_login_event("192.168.1.100", false);
            let signals = engine.evaluate_event(&ev).await.unwrap();
            assert!(signals.is_empty(), "Should not trigger under threshold");
        }

        // 10th failed login triggers BruteForceRule and creates Incident
        let ev10 = mock_login_event("192.168.1.100", false);
        let signals = engine.evaluate_event(&ev10).await.unwrap();
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].rule_name, "Credential Brute-Force / Password Spray");

        // Verify incident creation
        let incidents = engine.get_active_incidents().await;
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].target_entity, "user:attacker");
        assert_eq!(incidents[0].status, IncidentStatus::Open);
        assert_eq!(incidents[0].risk_score, 35);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_kernel_anomaly_detection() {
        let state = Arc::new(MemoryHotState::new());
        let engine = RuleEngine::with_default_rules(state);

        let kernel_ev = SecurityEvent {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            app_id: "payment-service".into(),
            environment: "prod".into(),
            event_type: "kernel.process_exec".into(),
            severity: Severity::Critical,
            actor: None,
            source: SourceContext {
                ip: Some("10.0.1.20".into()),
                port: None,
                user_agent: None,
                sensor: SensorMetadata {
                    sensor_type: SensorType::Tetragon,
                    raw_event_type: "process_exec".into(),
                    sensor_id: Some("tetragon-node-1".into()),
                    raw_payload: None,
                },
                container_id: Some("container-pay-prod-01".into()),
                pid: Some(4123),
                process_name: Some("/bin/bash".into()),
            },
            action: Some(ActionContext {
                method: None,
                endpoint: Some("/bin/bash -i".into()),
                status_code: None,
                duration_us: None,
                is_success: true,
                operation: Some("exec".into()),
            }),
            resource: None,
            metadata: std::collections::HashMap::new(),
            is_security_significant: true,
        };

        let signals = engine.evaluate_event(&kernel_ev).await.unwrap();
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].severity, Severity::Critical);
        assert_eq!(signals[0].rule_name, "Suspicious Container / Kernel Execution");

        let incidents = engine.get_active_incidents().await;
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].severity, Severity::Critical);
        assert_eq!(incidents[0].risk_score, 50);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_advisory_policy_gate_confidence_and_deny_precedence() {
        use security_control_plane_common::{
            AdvisoryRecommendation, ContainmentActionType, ControlPlaneMode, DecisionOutcome,
            PolicyBundle, PolicyRule, ThreatClassification,
        };

        let policy_engine = Arc::new(CapabilityPolicyEngine::new());
        // Configure policy bundle with explicit DENY on /bin/sh and protected auth-service
        let bundle = PolicyBundle {
            policy_id: "test-policy-v1".into(),
            version: 1,
            target_app: "*".into(),
            description: "Test policy with deny rules".into(),
            allow: vec![PolicyRule {
                capability: "session.revoke".into(),
                scope: "*".into(),
                description: Some("Allow revoking sessions".into()),
            }],
            deny: vec![
                PolicyRule {
                    capability: "service.isolate".into(),
                    scope: "auth-service".into(),
                    description: Some("Deny isolating critical auth service".into()),
                },
                PolicyRule {
                    capability: "process.execute".into(),
                    scope: "/bin/sh".into(),
                    description: Some("Deny shell".into()),
                },
            ],
            default_allow: false,
        };
        policy_engine.add_bundle(bundle).await;

        let containment_mgr = Arc::new(ContainmentManager::with_random_keypair());
        let advisory_mgr = AdvisoryManager::new(
            Arc::new(AdvisoryPolicyGate::new(
                Arc::clone(&policy_engine),
                Arc::clone(&containment_mgr),
                0.70,
            )),
            ControlPlaneMode::ModeA,
            "http://localhost:8000",
        );

        // 1. Initial mode should be Mode A
        assert_eq!(advisory_mgr.get_mode().await, ControlPlaneMode::ModeA);
        assert!(!advisory_mgr.is_mode_b().await);

        // Switch to Mode B
        advisory_mgr.set_mode(ControlPlaneMode::ModeB).await;
        assert_eq!(advisory_mgr.get_mode().await, ControlPlaneMode::ModeB);
        assert!(advisory_mgr.is_mode_b().await);

        // 2. Low confidence recommendation (< 0.70) must be REJECTED
        let low_conf_rec = AdvisoryRecommendation::new(
            Uuid::new_v4(),
            "user:test-user",
            "billing-app",
            ThreatClassification::Suspicious,
            0.55, // below 0.70
            vec!["LOW_CONFIDENCE_SIGNAL".into()],
            "Uncertain signal",
            ContainmentActionType::RevokeSession,
            Some("session.revoke".into()),
            HashMap::new(),
            300,
            "mock-llm",
        );
        let res1 = advisory_mgr.validate_and_enact(low_conf_rec).await;
        assert!(!res1.is_authorized);
        assert_eq!(res1.decision, DecisionOutcome::Deny);
        assert!(res1.rationale.contains("safety threshold"));

        // 3. Recommendation violating explicit DENY rule must be REJECTED
        let deny_rec = AdvisoryRecommendation::new(
            Uuid::new_v4(),
            "auth-service",
            "auth-service",
            ThreatClassification::Malicious,
            0.95,
            vec!["ANOMALOUS_BEHAVIOR".into()],
            "Isolate compromised auth service",
            ContainmentActionType::IsolateService,
            Some("service.isolate".into()),
            HashMap::new(),
            600,
            "mock-llm",
        );
        let res2 = advisory_mgr.validate_and_enact(deny_rec).await;
        assert!(!res2.is_authorized);
        assert_eq!(res2.decision, DecisionOutcome::Deny);
        assert!(res2.rationale.contains("REJECTED"));

        // 4. Recommendation authorized by policy must be APPROVED and signed
        let allow_rec = AdvisoryRecommendation::new(
            Uuid::new_v4(),
            "user:malicious-actor",
            "billing-app",
            ThreatClassification::Malicious,
            0.92,
            vec!["CREDENTIAL_STUFFING".into()],
            "High confidence credential stuffing",
            ContainmentActionType::RevokeSession,
            Some("session.revoke".into()),
            HashMap::new(),
            300,
            "mock-llm",
        );
        let res3 = advisory_mgr.validate_and_enact(allow_rec).await;
        assert!(res3.is_authorized);
        assert_eq!(res3.decision, DecisionOutcome::Allow);
        assert!(res3.containment_command_id.is_some());
    }
}
