mod error;
mod system;

pub use error::EnforcerError;
pub use system::SystemEnforcementBackend;

use async_trait::async_trait;
use chrono::Utc;
use security_control_plane_common::{
    ContainmentActionType, ContainmentStatus, SignedContainmentCommand,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{error, info};

#[async_trait]
pub trait EnforcementBackend: Send + Sync {
    async fn execute(&self, command: &SignedContainmentCommand) -> Result<(), EnforcerError>;
    async fn rollback(&self, command: &SignedContainmentCommand) -> Result<(), EnforcerError>;
}

pub struct NativeEnforcer {
    backend: Arc<dyn EnforcementBackend>,
    trusted_public_key: String,
    consumed_nonces: Mutex<HashMap<String, chrono::DateTime<Utc>>>,
}

impl NativeEnforcer {
    pub fn new(
        backend: Arc<dyn EnforcementBackend>,
        trusted_public_key: impl Into<String>,
    ) -> Self {
        Self {
            backend,
            trusted_public_key: trusted_public_key.into(),
            consumed_nonces: Mutex::new(HashMap::new()),
        }
    }

    pub fn system(trusted_public_key: impl Into<String>) -> Self {
        Self::new(
            Arc::new(SystemEnforcementBackend::new()),
            trusted_public_key,
        )
    }

    pub async fn execute(
        self: &Arc<Self>,
        command: &SignedContainmentCommand,
    ) -> Result<(), EnforcerError> {
        if command.status != ContainmentStatus::Active {
            return Err(EnforcerError::InactiveCommand);
        }
        if command.ttl_seconds == 0 || command.is_expired() {
            return Err(EnforcerError::ExpiredCommand);
        }
        if command.signer_public_key != self.trusted_public_key
            || !command
                .verify()
                .map_err(|_| EnforcerError::InvalidSignature)?
        {
            return Err(EnforcerError::InvalidSignature);
        }

        let now = Utc::now();
        let mut consumed = self.consumed_nonces.lock().await;
        consumed.retain(|_, expires_at| *expires_at > now);
        let nonce_key = format!("nonce:{}", command.nonce);
        let command_key = format!("command:{}", command.command_id);
        if consumed.contains_key(&nonce_key) || consumed.contains_key(&command_key) {
            return Err(EnforcerError::Replay);
        }

        let rollback_delay = if command.action == ContainmentActionType::NftablesBlock {
            Some(
                command
                    .expires_at
                    .signed_duration_since(Utc::now())
                    .to_std()
                    .map_err(|_| EnforcerError::ExpiredCommand)?,
            )
        } else {
            None
        };
        let execution_started = tokio::time::Instant::now();
        self.backend.execute(command).await?;
        consumed.insert(nonce_key, command.expires_at);
        consumed.insert(command_key, command.expires_at);
        drop(consumed);

        info!(
            command_id = %command.command_id,
            action = command.action.as_str(),
            "Executed signed native containment command"
        );

        if let Some(delay) = rollback_delay {
            let backend = Arc::clone(self);
            let command = command.clone();
            let delay = delay.saturating_sub(execution_started.elapsed());
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                if let Err(err) = backend.backend.rollback(&command).await {
                    error!(error = %err, command_id = %command.command_id, "Automatic containment rollback failed");
                } else {
                    info!(command_id = %command.command_id, "TTL-bounded nftables containment rolled back");
                }
            });
        }

        Ok(())
    }

    pub async fn rollback(&self, command: &SignedContainmentCommand) -> Result<(), EnforcerError> {
        if command.signer_public_key != self.trusted_public_key
            || !command
                .verify()
                .map_err(|_| EnforcerError::InvalidSignature)?
        {
            return Err(EnforcerError::InvalidSignature);
        }
        self.backend.rollback(command).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use security_control_plane_common::ControlPlaneKeypair;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct MockBackend {
        executions: AtomicUsize,
    }

    #[async_trait]
    impl EnforcementBackend for MockBackend {
        async fn execute(&self, _command: &SignedContainmentCommand) -> Result<(), EnforcerError> {
            self.executions.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn rollback(&self, _command: &SignedContainmentCommand) -> Result<(), EnforcerError> {
            Ok(())
        }
    }

    fn signed_command() -> SignedContainmentCommand {
        let keypair = ControlPlaneKeypair::generate();
        let mut command = SignedContainmentCommand::new(
            ContainmentActionType::KillProcess,
            "pid:1234",
            None,
            HashMap::new(),
            60,
            None,
            "process termination is irreversible",
        );
        command.sign(&keypair);
        command
    }

    #[tokio::test]
    async fn accepts_signed_command_once_and_rejects_replay() {
        let backend = Arc::new(MockBackend {
            executions: AtomicUsize::new(0),
        });
        let keypair = ControlPlaneKeypair::generate();
        let enforcer = Arc::new(NativeEnforcer::new(
            backend.clone(),
            keypair.public_key_hex(),
        ));
        let mut command = signed_command();
        command.sign(&keypair);

        enforcer.execute(&command).await.expect("first execution");
        assert!(matches!(
            enforcer.execute(&command).await,
            Err(EnforcerError::Replay)
        ));
        assert_eq!(backend.executions.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn rejects_tampered_command_before_backend_execution() {
        let backend = Arc::new(MockBackend {
            executions: AtomicUsize::new(0),
        });
        let keypair = ControlPlaneKeypair::generate();
        let enforcer = Arc::new(NativeEnforcer::new(
            backend.clone(),
            keypair.public_key_hex(),
        ));
        let mut command = signed_command();
        command.sign(&keypair);
        command.target_entity = "pid:9876".into();

        assert!(matches!(
            enforcer.execute(&command).await,
            Err(EnforcerError::InvalidSignature)
        ));
        assert_eq!(backend.executions.load(Ordering::SeqCst), 0);
    }
}
