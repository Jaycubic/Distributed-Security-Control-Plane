use crate::containment::ContainmentManager;
use crate::policy::CapabilityPolicyEngine;
use chrono::Utc;
use security_control_plane_common::{
    AdvisoryRecommendation, AdvisoryValidationResult, DecisionOutcome,
};
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

/// Deterministic Policy Validation Gate for Phase 6 Advisory Recommendations.
/// Enforces the core invariant: **Zero direct execution privileges for AI/LLMs**.
/// Every advisory recommendation must pass strict deterministic policy evaluation
/// where **DENY strictly takes precedence over ALLOW** before any command is signed.
pub struct AdvisoryPolicyGate {
    policy_engine: Arc<CapabilityPolicyEngine>,
    containment_mgr: Arc<ContainmentManager>,
    minimum_confidence: f64,
}

impl AdvisoryPolicyGate {
    pub fn new(
        policy_engine: Arc<CapabilityPolicyEngine>,
        containment_mgr: Arc<ContainmentManager>,
        minimum_confidence: f64,
    ) -> Self {
        Self {
            policy_engine,
            containment_mgr,
            minimum_confidence: minimum_confidence.clamp(0.1, 1.0),
        }
    }

    pub fn with_defaults(
        policy_engine: Arc<CapabilityPolicyEngine>,
        containment_mgr: Arc<ContainmentManager>,
    ) -> Self {
        // Minimum 0.70 confidence required for autonomous containment enforcement
        Self::new(policy_engine, containment_mgr, 0.70)
    }

    /// Evaluates an AdvisoryRecommendation against active deterministic capability policies.
    /// Returns an AdvisoryValidationResult indicating whether containment was authorized and issued.
    pub async fn validate_and_enact(
        &self,
        rec: &AdvisoryRecommendation,
    ) -> AdvisoryValidationResult {
        let validation_id = Uuid::new_v4();

        // 1. Minimum Confidence Gate Check
        if rec.confidence < self.minimum_confidence {
            warn!(
                recommendation_id = %rec.recommendation_id,
                confidence = rec.confidence,
                threshold = self.minimum_confidence,
                "Advisory recommendation rejected: confidence below deterministic safety threshold"
            );
            return AdvisoryValidationResult {
                validation_id,
                recommendation_id: rec.recommendation_id,
                incident_id: rec.incident_id,
                is_authorized: false,
                decision: DecisionOutcome::Deny,
                policy_id: "safety-confidence-gate".to_string(),
                rationale: format!(
                    "Recommendation confidence ({:.2}) is below required safety threshold ({:.2})",
                    rec.confidence, self.minimum_confidence
                ),
                containment_command_id: None,
                evaluated_at: Utc::now(),
            };
        }

        // 2. Derive Capability and Target Resource for Policy Evaluation
        let capability = rec
            .capability
            .clone()
            .unwrap_or_else(|| match rec.recommended_action {
                security_control_plane_common::ContainmentActionType::RevokeSession => {
                    "session.revoke".to_string()
                }
                security_control_plane_common::ContainmentActionType::ThrottleActor => {
                    "network.throttle".to_string()
                }
                security_control_plane_common::ContainmentActionType::BlockNetwork => {
                    "network.connect".to_string()
                }
                security_control_plane_common::ContainmentActionType::RevokeCapability => {
                    "capability.revoke".to_string()
                }
                security_control_plane_common::ContainmentActionType::RestrictScope => {
                    "scope.restrict".to_string()
                }
                security_control_plane_common::ContainmentActionType::IsolateService => {
                    "service.isolate".to_string()
                }
            });

        let target_resource = if let Some(res) = rec.params.get("resource") {
            res.clone()
        } else {
            rec.target_entity.clone()
        };

        // 3. Evaluate against Capability Policy Engine
        // DENY takes absolute precedence over ALLOW!
        let policy_decision = self
            .policy_engine
            .evaluate(
                &rec.app_id,
                "advisory-llm-worker",
                &rec.target_entity,
                &capability,
                &target_resource,
                vec![],
                false,
            )
            .await;

        if policy_decision.decision == DecisionOutcome::Deny {
            warn!(
                recommendation_id = %rec.recommendation_id,
                app_id = %rec.app_id,
                capability = %capability,
                policy_id = %policy_decision.policy_id,
                reason = %policy_decision.reason,
                "Deterministic policy gate REJECTED advisory recommendation (DENY rule enforced)"
            );

            return AdvisoryValidationResult {
                validation_id,
                recommendation_id: rec.recommendation_id,
                incident_id: rec.incident_id,
                is_authorized: false,
                decision: DecisionOutcome::Deny,
                policy_id: policy_decision.policy_id,
                rationale: format!(
                    "Deterministic policy gate REJECTED recommendation: {}",
                    policy_decision.reason
                ),
                containment_command_id: None,
                evaluated_at: Utc::now(),
            };
        }

        // 4. Authorized by Deterministic Policy: Dispatch Ed25519-Signed Containment Command
        let ttl_s = if rec.suggested_ttl_seconds > 0 {
            rec.suggested_ttl_seconds
        } else {
            300 // default 5 minutes
        };

        let rollback_recipe = format!(
            "Advisory rollback for incident {} recommendation {}",
            rec.incident_id, rec.recommendation_id
        );

        let signed_cmd = self
            .containment_mgr
            .dispatch(
                rec.recommended_action.clone(),
                rec.target_entity.clone(),
                rec.capability.clone(),
                rec.params.clone(),
                ttl_s,
                Some(rec.incident_id),
                rollback_recipe,
            )
            .await;

        info!(
            recommendation_id = %rec.recommendation_id,
            command_id = %signed_cmd.command_id,
            action = signed_cmd.action.as_str(),
            target = %signed_cmd.target_entity,
            ttl_s = signed_cmd.ttl_seconds,
            "Deterministic policy gate APPROVED advisory recommendation and issued signed containment"
        );

        AdvisoryValidationResult {
            validation_id,
            recommendation_id: rec.recommendation_id,
            incident_id: rec.incident_id,
            is_authorized: true,
            decision: DecisionOutcome::Allow,
            policy_id: policy_decision.policy_id,
            rationale: format!(
                "Approved by policy. Issued Ed25519-signed containment command {} (TTL: {}s)",
                signed_cmd.command_id, signed_cmd.ttl_seconds
            ),
            containment_command_id: Some(signed_cmd.command_id),
            evaluated_at: Utc::now(),
        }
    }
}
