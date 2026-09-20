use crate::crypto::{verify_signature, ControlPlaneKeypair, CryptoError};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContainmentActionType {
    RevokeSession,
    ThrottleActor,
    BlockNetwork,
    RevokeCapability,
    RestrictScope,
    IsolateService,
}

impl ContainmentActionType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::RevokeSession => "REVOKE_SESSION",
            Self::ThrottleActor => "THROTTLE_ACTOR",
            Self::BlockNetwork => "BLOCK_NETWORK",
            Self::RevokeCapability => "REVOKE_CAPABILITY",
            Self::RestrictScope => "RESTRICT_SCOPE",
            Self::IsolateService => "ISOLATE_SERVICE",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "REVOKE_SESSION" => Self::RevokeSession,
            "THROTTLE_ACTOR" => Self::ThrottleActor,
            "BLOCK_NETWORK" => Self::BlockNetwork,
            "REVOKE_CAPABILITY" => Self::RevokeCapability,
            "RESTRICT_SCOPE" => Self::RestrictScope,
            "ISOLATE_SERVICE" => Self::IsolateService,
            _ => Self::ThrottleActor,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContainmentStatus {
    Active,
    Expired,
    RolledBack,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignedContainmentCommand {
    pub command_id: Uuid,
    pub action: ContainmentActionType,
    pub target_entity: String,
    pub capability: Option<String>,
    pub params: HashMap<String, String>,
    pub ttl_seconds: u64,
    pub nonce: String,
    pub evidence_incident_id: Option<Uuid>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub signer_public_key: String,
    pub signature: String,
    pub status: ContainmentStatus,
    pub rollback_recipe: String,
}

impl SignedContainmentCommand {
    /// Constructs a new unsigned containment command with calculated expiration.
    pub fn new(
        action: ContainmentActionType,
        target_entity: impl Into<String>,
        capability: Option<String>,
        params: HashMap<String, String>,
        ttl_seconds: u64,
        evidence_incident_id: Option<Uuid>,
        rollback_recipe: impl Into<String>,
    ) -> Self {
        let now = Utc::now();
        let expires_at = now + Duration::seconds(ttl_seconds as i64);
        let nonce = format!("{}-{}", now.timestamp_millis(), Uuid::new_v4().simple());

        Self {
            command_id: Uuid::new_v4(),
            action,
            target_entity: target_entity.into(),
            capability,
            params,
            ttl_seconds,
            nonce,
            evidence_incident_id,
            issued_at: now,
            expires_at,
            signer_public_key: String::new(),
            signature: String::new(),
            status: ContainmentStatus::Active,
            rollback_recipe: rollback_recipe.into(),
        }
    }

    /// Computes the deterministic canonical byte sequence over which the signature is formed.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let incident_str = self
            .evidence_incident_id
            .map(|id| id.to_string())
            .unwrap_or_else(|| "none".to_string());
        let cap_str = self.capability.as_deref().unwrap_or("none");

        // Sort params keys deterministically
        let mut sorted_params = self.params.iter().collect::<Vec<_>>();
        sorted_params.sort_by_key(|(k, _)| *k);
        let params_str = sorted_params
            .into_iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(";");

        let canonical = format!(
            "CMD_ID:{}\nACTION:{}\nTARGET:{}\nCAP:{}\nPARAMS:{}\nTTL:{}\nNONCE:{}\nINCIDENT:{}\nISSUED:{}\nEXPIRES:{}\nRECIPE:{}",
            self.command_id,
            self.action.as_str(),
            self.target_entity,
            cap_str,
            params_str,
            self.ttl_seconds,
            self.nonce,
            incident_str,
            self.issued_at.to_rfc3339(),
            self.expires_at.to_rfc3339(),
            self.rollback_recipe
        );
        canonical.into_bytes()
    }

    /// Signs this command in-place using the control plane keypair.
    pub fn sign(&mut self, keypair: &ControlPlaneKeypair) {
        self.signer_public_key = keypair.public_key_hex();
        let bytes = self.canonical_bytes();
        self.signature = keypair.sign(&bytes);
    }

    /// Cryptographically verifies the command signature against its signer public key.
    pub fn verify(&self) -> Result<bool, CryptoError> {
        let bytes = self.canonical_bytes();
        verify_signature(&self.signer_public_key, &bytes, &self.signature)
    }

    /// Checks if the command TTL has elapsed.
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signed_containment_command_lifecycle() {
        let keypair = ControlPlaneKeypair::generate();
        let mut params = HashMap::new();
        params.insert("rate_limit".into(), "10/m".into());

        let mut cmd = SignedContainmentCommand::new(
            ContainmentActionType::ThrottleActor,
            "ip:198.51.100.200",
            None,
            params,
            300,
            None,
            "REMOVE_THROTTLE_RATE_LIMIT",
        );

        assert_eq!(cmd.status, ContainmentStatus::Active);
        assert!(!cmd.is_expired());

        // Sign command
        cmd.sign(&keypair);
        assert!(!cmd.signature.is_empty());
        assert!(!cmd.signer_public_key.is_empty());

        // Verify valid signature
        assert!(cmd.verify().expect("verification failed"));

        // Verify tampering target entity invalidates signature
        let mut tampered = cmd.clone();
        tampered.target_entity = "ip:198.51.100.201".into();
        assert!(tampered.verify().is_err());
    }
}
