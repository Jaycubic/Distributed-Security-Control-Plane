use chrono::{DateTime, Utc};
use security_control_plane_common::{
    verify_signature, ContainmentActionType, CryptoError, NonceTracker, SignedContainmentCommand,
};
use std::collections::HashMap;
use std::sync::Mutex;
use tracing::{info, warn};

/// In-process, sub-microsecond local enforcement guard for protected application workloads.
/// Cryptographically validates signed containment commands from the Control Plane
/// and enforces active restrictions locally with automated TTL expiration.
pub struct ContainmentGuard {
    trusted_public_key_hex: String,
    nonce_tracker: NonceTracker,
    blocked_ips: Mutex<HashMap<String, DateTime<Utc>>>,
    revoked_sessions: Mutex<HashMap<String, DateTime<Utc>>>,
    revoked_capabilities: Mutex<HashMap<(String, String), DateTime<Utc>>>,
}

impl ContainmentGuard {
    pub fn new(trusted_public_key_hex: impl Into<String>) -> Self {
        Self {
            trusted_public_key_hex: trusted_public_key_hex.into(),
            nonce_tracker: NonceTracker::new(60),
            blocked_ips: Mutex::new(HashMap::new()),
            revoked_sessions: Mutex::new(HashMap::new()),
            revoked_capabilities: Mutex::new(HashMap::new()),
        }
    }

    /// Verifies cryptographic signature, replay protection, and applies containment command locally.
    pub fn apply_command(&self, cmd: &SignedContainmentCommand) -> Result<bool, CryptoError> {
        // 1. Verify signer public key matches trusted control plane key
        if cmd.signer_public_key != self.trusted_public_key_hex {
            warn!(
                expected = %self.trusted_public_key_hex,
                actual = %cmd.signer_public_key,
                "Containment command rejected: Signer public key does not match trusted control plane"
            );
            return Err(CryptoError::VerificationFailed);
        }

        // 2. Cryptographically verify signature over canonical payload
        let canonical_bytes = cmd.canonical_bytes();
        verify_signature(&cmd.signer_public_key, &canonical_bytes, &cmd.signature)?;

        // 3. Check replay nonce & clock skew
        self.nonce_tracker.check_and_record(&cmd.nonce, cmd.issued_at)?;

        // 4. Check if command is already expired
        if cmd.is_expired() {
            warn!(command_id = %cmd.command_id, "Containment command rejected: Already expired");
            return Ok(false);
        }

        // 5. Apply to local fast memory tables
        match cmd.action {
            ContainmentActionType::BlockNetwork => {
                let mut ips = self.blocked_ips.lock().unwrap();
                let clean_ip = cmd.target_entity.trim_start_matches("ip:").to_string();
                ips.insert(clean_ip, cmd.expires_at);
            }
            ContainmentActionType::RevokeSession => {
                let mut sessions = self.revoked_sessions.lock().unwrap();
                let clean_sess = cmd.target_entity.trim_start_matches("session:").to_string();
                sessions.insert(clean_sess, cmd.expires_at);
            }
            ContainmentActionType::RevokeCapability => {
                if let Some(ref cap) = cmd.capability {
                    let mut caps = self.revoked_capabilities.lock().unwrap();
                    caps.insert((cmd.target_entity.clone(), cap.clone()), cmd.expires_at);
                }
            }
            _ => {
                // Other actions (throttle, isolate) stored under target entity
                let mut sessions = self.revoked_sessions.lock().unwrap();
                sessions.insert(cmd.target_entity.clone(), cmd.expires_at);
            }
        }

        info!(
            command_id = %cmd.command_id,
            action = cmd.action.as_str(),
            target = %cmd.target_entity,
            "Signed containment command verified and active in local agent cache"
        );

        Ok(true)
    }

    /// Explicitly rolls back an action from local enforcement.
    pub fn rollback_action(&self, target_entity: &str, action: ContainmentActionType) {
        match action {
            ContainmentActionType::BlockNetwork => {
                let mut ips = self.blocked_ips.lock().unwrap();
                let clean_ip = target_entity.trim_start_matches("ip:");
                ips.remove(clean_ip);
            }
            ContainmentActionType::RevokeSession => {
                let mut sessions = self.revoked_sessions.lock().unwrap();
                let clean_sess = target_entity.trim_start_matches("session:");
                sessions.remove(clean_sess);
            }
            ContainmentActionType::RevokeCapability => {
                let mut caps = self.revoked_capabilities.lock().unwrap();
                caps.retain(|(target, _), _| target != target_entity);
            }
            _ => {
                let mut sessions = self.revoked_sessions.lock().unwrap();
                sessions.remove(target_entity);
            }
        }
    }

    /// Fast sub-microsecond check: is source IP currently blocked?
    pub fn is_ip_blocked(&self, ip: &str) -> bool {
        let clean_ip = ip.trim_start_matches("ip:");
        let now = Utc::now();
        let mut ips = self.blocked_ips.lock().unwrap();
        if let Some(&expires_at) = ips.get(clean_ip) {
            if now < expires_at {
                return true;
            } else {
                // Expired TTL -> automatically evict
                ips.remove(clean_ip);
            }
        }
        false
    }

    /// Fast sub-microsecond check: is session token currently revoked?
    pub fn is_session_revoked(&self, session_id: &str) -> bool {
        let clean_sess = session_id.trim_start_matches("session:");
        let now = Utc::now();
        let mut sessions = self.revoked_sessions.lock().unwrap();
        if let Some(&expires_at) = sessions.get(clean_sess) {
            if now < expires_at {
                return true;
            } else {
                // Expired TTL -> automatically evict
                sessions.remove(clean_sess);
            }
        }
        false
    }

    /// Fast sub-microsecond check: is specific capability revoked for entity?
    pub fn is_capability_revoked(&self, target_entity: &str, capability: &str) -> bool {
        let now = Utc::now();
        let mut caps = self.revoked_capabilities.lock().unwrap();
        let key = (target_entity.to_string(), capability.to_string());
        if let Some(&expires_at) = caps.get(&key) {
            if now < expires_at {
                return true;
            } else {
                caps.remove(&key);
            }
        }
        false
    }

    /// Comprehensive request check: returns false if IP blocked, session revoked, or capability revoked.
    pub fn is_request_allowed(
        &self,
        ip: Option<&str>,
        session_id: Option<&str>,
        capability: Option<&str>,
    ) -> bool {
        if let Some(i) = ip {
            if self.is_ip_blocked(i) {
                return false;
            }
        }
        if let Some(s) = session_id {
            if self.is_session_revoked(s) {
                return false;
            }
        }
        if let (Some(s), Some(c)) = (session_id, capability) {
            if self.is_capability_revoked(s, c) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use security_control_plane_common::ControlPlaneKeypair;

    #[test]
    fn test_containment_guard_verification_and_eviction() {
        let keypair = ControlPlaneKeypair::generate();
        let guard = ContainmentGuard::new(keypair.public_key_hex());

        let mut cmd = SignedContainmentCommand::new(
            ContainmentActionType::BlockNetwork,
            "ip:198.51.100.55",
            None,
            HashMap::new(),
            60,
            None,
            "UNBLOCK",
        );
        cmd.sign(&keypair);

        // Apply command
        assert!(guard.apply_command(&cmd).expect("verification error"));
        assert!(guard.is_ip_blocked("198.51.100.55"));
        assert!(!guard.is_ip_blocked("198.51.100.56"));

        // Rollback
        guard.rollback_action("ip:198.51.100.55", ContainmentActionType::BlockNetwork);
        assert!(!guard.is_ip_blocked("198.51.100.55"));
    }
}
