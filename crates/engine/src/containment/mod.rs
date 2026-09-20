use chrono::Utc;
use security_control_plane_common::{
    ContainmentActionType, ContainmentStatus, ControlPlaneKeypair, SignedContainmentCommand,
};
use std::collections::HashMap;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::info;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum ContainmentError {
    #[error("Containment command {0} not found")]
    NotFound(Uuid),
    #[error("Command {0} is already rolled back")]
    AlreadyRolledBack(Uuid),
    #[error("Command {0} is already expired")]
    AlreadyExpired(Uuid),
}

/// Central state manager for active, expired, and rolled-back containment actions.
/// Cryptographically signs commands using an Ed25519 keypair and enforces TTLs.
pub struct ContainmentManager {
    keypair: ControlPlaneKeypair,
    commands: RwLock<HashMap<Uuid, SignedContainmentCommand>>,
}

impl ContainmentManager {
    /// Creates a new ContainmentManager with an existing or freshly generated keypair.
    pub fn new(keypair: ControlPlaneKeypair) -> Self {
        Self {
            keypair,
            commands: RwLock::new(HashMap::new()),
        }
    }

    /// Creates a new ContainmentManager with a freshly generated random Ed25519 keypair.
    pub fn with_random_keypair() -> Self {
        Self::new(ControlPlaneKeypair::generate())
    }

    /// Returns the hex-encoded 32-byte Ed25519 public key.
    pub fn public_key_hex(&self) -> String {
        self.keypair.public_key_hex()
    }

    /// Dispatches a new surgical containment command, signed with Ed25519 and stamped with a TTL.
    pub async fn dispatch(
        &self,
        action: ContainmentActionType,
        target_entity: impl Into<String>,
        capability: Option<String>,
        params: HashMap<String, String>,
        ttl_seconds: u64,
        evidence_incident_id: Option<Uuid>,
        rollback_recipe: impl Into<String>,
    ) -> SignedContainmentCommand {
        let mut cmd = SignedContainmentCommand::new(
            action,
            target_entity,
            capability,
            params,
            ttl_seconds,
            evidence_incident_id,
            rollback_recipe,
        );

        // Sign the canonical byte payload with the control plane keypair
        cmd.sign(&self.keypair);

        info!(
            command_id = %cmd.command_id,
            action = cmd.action.as_str(),
            target = %cmd.target_entity,
            ttl_s = cmd.ttl_seconds,
            "Dispatched Ed25519-signed containment command"
        );

        let mut lock = self.commands.write().await;
        lock.insert(cmd.command_id, cmd.clone());
        cmd
    }

    /// Explicitly rolls back an active containment command before its TTL expires.
    pub async fn rollback(
        &self,
        command_id: Uuid,
        operator_reason: &str,
    ) -> Result<SignedContainmentCommand, ContainmentError> {
        let mut lock = self.commands.write().await;
        let cmd = lock
            .get_mut(&command_id)
            .ok_or(ContainmentError::NotFound(command_id))?;

        if cmd.status == ContainmentStatus::RolledBack {
            return Err(ContainmentError::AlreadyRolledBack(command_id));
        }
        if cmd.status == ContainmentStatus::Expired {
            return Err(ContainmentError::AlreadyExpired(command_id));
        }

        cmd.status = ContainmentStatus::RolledBack;
        info!(
            command_id = %command_id,
            action = cmd.action.as_str(),
            target = %cmd.target_entity,
            reason = %operator_reason,
            "Rolled back containment command"
        );

        Ok(cmd.clone())
    }

    /// Sweeps all active commands and marks any whose TTL has elapsed as Expired.
    pub async fn sweep_expired(&self) -> Vec<Uuid> {
        let mut lock = self.commands.write().await;
        let now = Utc::now();
        let mut expired_ids = Vec::new();

        for (id, cmd) in lock.iter_mut() {
            if cmd.status == ContainmentStatus::Active && now >= cmd.expires_at {
                cmd.status = ContainmentStatus::Expired;
                expired_ids.push(*id);
                info!(
                    command_id = %id,
                    target = %cmd.target_entity,
                    "Containment command TTL expired; automatically transitioned to Expired"
                );
            }
        }

        expired_ids
    }

    /// Checks if a session ID is currently revoked under an active containment command.
    pub async fn is_session_revoked(&self, session_id: &str) -> bool {
        let lock = self.commands.read().await;
        let now = Utc::now();
        for cmd in lock.values() {
            if cmd.status == ContainmentStatus::Active
                && cmd.action == ContainmentActionType::RevokeSession
                && now < cmd.expires_at
            {
                if cmd.target_entity == session_id
                    || cmd.target_entity == format!("session:{}", session_id)
                {
                    return true;
                }
            }
        }
        false
    }

    /// Checks if a source IP is currently blocked under an active containment command.
    pub async fn is_ip_blocked(&self, ip: &str) -> bool {
        let lock = self.commands.read().await;
        let now = Utc::now();
        for cmd in lock.values() {
            if cmd.status == ContainmentStatus::Active
                && cmd.action == ContainmentActionType::BlockNetwork
                && now < cmd.expires_at
            {
                if cmd.target_entity == ip || cmd.target_entity == format!("ip:{}", ip) {
                    return true;
                }
            }
        }
        false
    }

    /// Checks if a specific capability is revoked for a target entity.
    pub async fn is_capability_revoked(&self, entity: &str, capability: &str) -> bool {
        let lock = self.commands.read().await;
        let now = Utc::now();
        for cmd in lock.values() {
            if cmd.status == ContainmentStatus::Active
                && cmd.action == ContainmentActionType::RevokeCapability
                && now < cmd.expires_at
            {
                if (cmd.target_entity == entity || entity.contains(&cmd.target_entity))
                    && cmd.capability.as_deref() == Some(capability)
                {
                    return true;
                }
            }
        }
        false
    }

    /// Retrieves all containment commands, optionally filtered to only active ones.
    pub async fn get_commands(&self, active_only: bool) -> Vec<SignedContainmentCommand> {
        let lock = self.commands.read().await;
        let now = Utc::now();
        lock.values()
            .filter(|c| {
                if active_only {
                    c.status == ContainmentStatus::Active && now < c.expires_at
                } else {
                    true
                }
            })
            .cloned()
            .collect()
    }

    /// Retrieves a single containment command by ID.
    pub async fn get_command(&self, id: Uuid) -> Option<SignedContainmentCommand> {
        let lock = self.commands.read().await;
        lock.get(&id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dispatch_and_rollback_flow() {
        let manager = ContainmentManager::with_random_keypair();

        let cmd = manager
            .dispatch(
                ContainmentActionType::RevokeSession,
                "session:sess_malicious_99",
                None,
                HashMap::new(),
                300,
                None,
                "REINSTATE_SESSION_REDIS",
            )
            .await;

        assert_eq!(cmd.status, ContainmentStatus::Active);
        assert!(manager.is_session_revoked("sess_malicious_99").await);
        assert!(!manager.is_session_revoked("sess_legitimate_01").await);

        // Verify valid cryptographic signature
        assert!(cmd.verify().expect("verification failed"));

        // Rollback command
        let rolled_back = manager
            .rollback(cmd.command_id, "Operator verified false positive")
            .await
            .expect("rollback failed");

        assert_eq!(rolled_back.status, ContainmentStatus::RolledBack);
        assert!(!manager.is_session_revoked("sess_malicious_99").await);
    }
}
