use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::sync::Mutex;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Invalid public key hex or bytes: {0}")]
    InvalidPublicKey(String),
    #[error("Invalid signature hex or bytes: {0}")]
    InvalidSignature(String),
    #[error("Signature verification failed")]
    VerificationFailed,
    #[error("Replay attack detected: Nonce '{0}' has already been processed")]
    NonceReplayed(String),
    #[error("Clock skew error: Command timestamp skewed by more than allowed window ({0}s)")]
    ClockSkew(i64),
}

/// Helper struct that holds the Ed25519 keypair for the Security Control Plane.
#[derive(Clone)]
pub struct ControlPlaneKeypair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl ControlPlaneKeypair {
    /// Generates a new random Ed25519 keypair.
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Creates a keypair from a 32-byte secret key seed.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(bytes);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Returns the hex-encoded 32-byte public key.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.verifying_key.as_bytes())
    }

    /// Signs an arbitrary canonical byte slice and returns the 64-byte Ed25519 signature in hex.
    pub fn sign(&self, canonical_bytes: &[u8]) -> String {
        let signature: Signature = self.signing_key.sign(canonical_bytes);
        hex::encode(signature.to_bytes())
    }

    /// Returns a copy of the verifying key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.verifying_key
    }
}

/// Verifies an Ed25519 hex signature over canonical bytes given a hex public key.
pub fn verify_signature(
    public_key_hex: &str,
    canonical_bytes: &[u8],
    signature_hex: &str,
) -> Result<bool, CryptoError> {
    let pubkey_bytes = hex::decode(public_key_hex)
        .map_err(|e| CryptoError::InvalidPublicKey(format!("Hex decode error: {}", e)))?;

    if pubkey_bytes.len() != 32 {
        return Err(CryptoError::InvalidPublicKey(format!(
            "Expected 32 bytes, got {}",
            pubkey_bytes.len()
        )));
    }

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&pubkey_bytes);

    let verifying_key = VerifyingKey::from_bytes(&key_arr)
        .map_err(|e| CryptoError::InvalidPublicKey(format!("Ed25519 key error: {}", e)))?;

    let sig_bytes = hex::decode(signature_hex)
        .map_err(|e| CryptoError::InvalidSignature(format!("Hex decode error: {}", e)))?;

    if sig_bytes.len() != 64 {
        return Err(CryptoError::InvalidSignature(format!(
            "Expected 64 bytes, got {}",
            sig_bytes.len()
        )));
    }

    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| CryptoError::InvalidSignature(format!("Ed25519 sig error: {}", e)))?;

    verifying_key
        .verify(canonical_bytes, &signature)
        .map(|_| true)
        .map_err(|_| CryptoError::VerificationFailed)
}

/// Replay-protection tracker keeping observed nonces and rejecting duplicates.
/// Evicts nonces older than `retention_duration`.
pub struct NonceTracker {
    seen_nonces: Mutex<HashMap<String, DateTime<Utc>>>,
    max_skew_seconds: i64,
    retention: Duration,
}

impl NonceTracker {
    pub fn new(max_skew_seconds: i64) -> Self {
        Self {
            seen_nonces: Mutex::new(HashMap::new()),
            max_skew_seconds,
            retention: Duration::minutes(15),
        }
    }

    /// Verifies that a nonce has not been seen before, and that the command timestamp is within clock skew.
    pub fn check_and_record(
        &self,
        nonce: &str,
        command_timestamp: DateTime<Utc>,
    ) -> Result<(), CryptoError> {
        let now = Utc::now();
        let diff = (now - command_timestamp).num_seconds().abs();
        if diff > self.max_skew_seconds {
            return Err(CryptoError::ClockSkew(diff));
        }

        let mut lock = self.seen_nonces.lock().unwrap();

        // Evict expired nonces
        let cutoff = now - self.retention;
        lock.retain(|_, ts| *ts > cutoff);

        if lock.contains_key(nonce) {
            return Err(CryptoError::NonceReplayed(nonce.to_string()));
        }

        lock.insert(nonce.to_string(), command_timestamp);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_sign_and_verify_cycle() {
        let kp = ControlPlaneKeypair::generate();
        let pubkey_hex = kp.public_key_hex();
        let payload = b"ACTION:REVOKE_SESSION:target=sess_123:ttl=300";

        let sig_hex = kp.sign(payload);
        assert_eq!(sig_hex.len(), 128); // 64 bytes in hex = 128 chars

        let valid = verify_signature(&pubkey_hex, payload, &sig_hex).expect("verification failed");
        assert!(valid);

        // Tamper payload
        let tampered = b"ACTION:REVOKE_SESSION:target=sess_124:ttl=300";
        let tampered_res = verify_signature(&pubkey_hex, tampered, &sig_hex);
        assert!(tampered_res.is_err());
    }

    #[test]
    fn test_nonce_replay_protection() {
        let tracker = NonceTracker::new(60);
        let now = Utc::now();

        assert!(tracker.check_and_record("nonce_abc", now).is_ok());
        // Replay should fail
        assert!(tracker.check_and_record("nonce_abc", now).is_err());

        // Skewed timestamp should fail
        let skewed = now - Duration::seconds(120);
        assert!(tracker.check_and_record("nonce_xyz", skewed).is_err());
    }
}
