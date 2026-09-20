use chrono::Utc;
use security_control_plane_common::{
    DecisionOutcome, PolicyBundle, PolicyDecision, PolicyRule,
};
use std::collections::HashMap;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Deno-inspired Capability Policy Engine.
/// Implements explicit Allow/Deny rule evaluation with the core invariant:
/// **DENY strictly takes precedence over ALLOW**.
pub struct CapabilityPolicyEngine {
    bundles: RwLock<HashMap<String, PolicyBundle>>,
}

impl CapabilityPolicyEngine {
    pub fn new() -> Self {
        let engine = Self {
            bundles: RwLock::new(HashMap::new()),
        };
        engine
    }

    /// Creates an engine pre-loaded with default production baseline policies.
    pub fn with_default_policies() -> Self {
        let default_bundle = PolicyBundle {
            policy_id: "default-app-baseline-v1".into(),
            version: 1,
            target_app: "*".into(),
            description: "Default baseline capability policy with strict security denies".into(),
            allow: vec![
                PolicyRule {
                    capability: "database.read".into(),
                    scope: "/app/data/**".into(),
                    description: Some("Allow standard application data access".into()),
                },
                PolicyRule {
                    capability: "network.connect".into(),
                    scope: "*.internal:*".into(),
                    description: Some("Allow internal microservice communication".into()),
                },
                PolicyRule {
                    capability: "session.authenticate".into(),
                    scope: "*".into(),
                    description: Some("Allow standard user authentication".into()),
                },
            ],
            deny: vec![
                PolicyRule {
                    capability: "process.execute".into(),
                    scope: "/bin/sh".into(),
                    description: Some("Deny spawning shell in containers".into()),
                },
                PolicyRule {
                    capability: "process.execute".into(),
                    scope: "/bin/bash".into(),
                    description: Some("Deny spawning bash in containers".into()),
                },
                PolicyRule {
                    capability: "filesystem.read".into(),
                    scope: "/etc/shadow".into(),
                    description: Some("Deny credential file reads".into()),
                },
                PolicyRule {
                    capability: "filesystem.read".into(),
                    scope: "/etc/**".into(),
                    description: Some("Deny host config reads".into()),
                },
                PolicyRule {
                    capability: "network.connect".into(),
                    scope: "169.254.169.254:*".into(),
                    description: Some("Deny AWS/Cloud metadata access (SSRF)".into()),
                },
            ],
            default_allow: false,
        };

        // Put in initial bundle synchronously
        let mut map = HashMap::new();
        map.insert(default_bundle.policy_id.clone(), default_bundle);
        Self {
            bundles: RwLock::new(map),
        }
    }

    /// Adds or updates a policy bundle.
    pub async fn add_bundle(&self, bundle: PolicyBundle) {
        let mut lock = self.bundles.write().await;
        lock.insert(bundle.policy_id.clone(), bundle);
    }

    /// Removes a policy bundle by ID.
    pub async fn remove_bundle(&self, policy_id: &str) -> bool {
        let mut lock = self.bundles.write().await;
        lock.remove(policy_id).is_some()
    }

    /// Retrieves all active policy bundles.
    pub async fn get_bundles(&self) -> Vec<PolicyBundle> {
        let lock = self.bundles.read().await;
        lock.values().cloned().collect()
    }

    /// Retrieves a single policy bundle by ID.
    pub async fn get_bundle(&self, policy_id: &str) -> Option<PolicyBundle> {
        let lock = self.bundles.read().await;
        lock.get(policy_id).cloned()
    }

    /// Evaluates a requested capability and resource access against active policies.
    /// Invariant: **DENY strictly overrides ALLOW**.
    pub async fn evaluate(
        &self,
        app_id: &str,
        who: &str,
        _actor_entity: &str,
        capability: &str,
        resource: &str,
        evidence_event_ids: Vec<Uuid>,
        is_simulation: bool,
    ) -> PolicyDecision {
        let lock = self.bundles.read().await;

        // Filter applicable bundles: matching app_id or global wildcard "*"
        let applicable: Vec<&PolicyBundle> = lock
            .values()
            .filter(|b| b.target_app == "*" || b.target_app == app_id)
            .collect();

        if applicable.is_empty() {
            return PolicyDecision {
                decision_id: Uuid::new_v4(),
                who: who.to_string(),
                app_id: app_id.to_string(),
                capability: capability.to_string(),
                target_resource: resource.to_string(),
                policy_id: "none".to_string(),
                decision: DecisionOutcome::Deny,
                reason: "No matching policy bundle found for application (default-deny)".into(),
                matched_rule: None,
                is_simulation,
                evidence_event_ids,
                timestamp: Utc::now(),
            };
        }

        // STEP 1: Check all DENY rules across applicable bundles.
        // DENY TAKES ABSOLUTE PRECEDENCE OVER ALLOW!
        for bundle in &applicable {
            for deny_rule in &bundle.deny {
                if deny_rule.matches(capability, resource) {
                    return PolicyDecision {
                        decision_id: Uuid::new_v4(),
                        who: who.to_string(),
                        app_id: app_id.to_string(),
                        capability: capability.to_string(),
                        target_resource: resource.to_string(),
                        policy_id: bundle.policy_id.clone(),
                        decision: DecisionOutcome::Deny,
                        reason: format!(
                            "Explicit DENY rule matched: '{}' on scope '{}' (precedence over allow)",
                            deny_rule.capability, deny_rule.scope
                        ),
                        matched_rule: Some(format!("DENY: {} -> {}", deny_rule.capability, deny_rule.scope)),
                        is_simulation,
                        evidence_event_ids,
                        timestamp: Utc::now(),
                    };
                }
            }
        }

        // STEP 2: Check ALLOW rules.
        for bundle in &applicable {
            for allow_rule in &bundle.allow {
                if allow_rule.matches(capability, resource) {
                    return PolicyDecision {
                        decision_id: Uuid::new_v4(),
                        who: who.to_string(),
                        app_id: app_id.to_string(),
                        capability: capability.to_string(),
                        target_resource: resource.to_string(),
                        policy_id: bundle.policy_id.clone(),
                        decision: DecisionOutcome::Allow,
                        reason: format!(
                            "Explicit ALLOW rule matched: '{}' on scope '{}'",
                            allow_rule.capability, allow_rule.scope
                        ),
                        matched_rule: Some(format!("ALLOW: {} -> {}", allow_rule.capability, allow_rule.scope)),
                        is_simulation,
                        evidence_event_ids,
                        timestamp: Utc::now(),
                    };
                }
            }
        }

        // STEP 3: Fall back to default policy (check default_allow flag, otherwise default DENY)
        let primary_bundle = applicable[0];
        if primary_bundle.default_allow {
            PolicyDecision {
                decision_id: Uuid::new_v4(),
                who: who.to_string(),
                app_id: app_id.to_string(),
                capability: capability.to_string(),
                target_resource: resource.to_string(),
                policy_id: primary_bundle.policy_id.clone(),
                decision: DecisionOutcome::Allow,
                reason: "Allowed by bundle default_allow fallback".into(),
                matched_rule: None,
                is_simulation,
                evidence_event_ids,
                timestamp: Utc::now(),
            }
        } else {
            PolicyDecision {
                decision_id: Uuid::new_v4(),
                who: who.to_string(),
                app_id: app_id.to_string(),
                capability: capability.to_string(),
                target_resource: resource.to_string(),
                policy_id: primary_bundle.policy_id.clone(),
                decision: DecisionOutcome::Deny,
                reason: "Access denied by default: No matching allow rule found in active policies".into(),
                matched_rule: None,
                is_simulation,
                evidence_event_ids,
                timestamp: Utc::now(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_deny_overrides_allow_precedence() {
        let engine = CapabilityPolicyEngine::new();

        // Create a policy where database.read is both allowed on /app/data/**
        // and explicitly denied on /app/data/passwords/**
        let bundle = PolicyBundle {
            policy_id: "test-policy-1".into(),
            version: 1,
            target_app: "billing-svc".into(),
            description: "Test precedence".into(),
            allow: vec![PolicyRule {
                capability: "database.read".into(),
                scope: "/app/data/**".into(),
                description: None,
            }],
            deny: vec![PolicyRule {
                capability: "database.read".into(),
                scope: "/app/data/passwords/**".into(),
                description: None,
            }],
            default_allow: false,
        };

        engine.add_bundle(bundle).await;

        // Regular data path should be Allowed
        let decision1 = engine
            .evaluate("billing-svc", "user_1", "ip:10.0.0.1", "database.read", "/app/data/orders", vec![], false)
            .await;
        assert_eq!(decision1.decision, DecisionOutcome::Allow);

        // Conflicting path MUST be Denied because DENY strictly overrides ALLOW!
        let decision2 = engine
            .evaluate("billing-svc", "user_1", "ip:10.0.0.1", "database.read", "/app/data/passwords/hash", vec![], false)
            .await;
        assert_eq!(decision2.decision, DecisionOutcome::Deny);
        assert!(decision2.reason.contains("precedence over allow"));
    }

    #[tokio::test]
    async fn test_mode_c_simulation() {
        let engine = CapabilityPolicyEngine::with_default_policies();

        // Simulate spawning shell in container
        let decision = engine
            .evaluate("payment-svc", "container_root", "pod:pay-01", "process.execute", "/bin/sh", vec![], true)
            .await;

        assert_eq!(decision.decision, DecisionOutcome::Deny);
        assert!(decision.is_simulation);
        assert!(decision.matched_rule.is_some());
    }
}
