#[derive(Debug, thiserror::Error)]
pub enum EnforcerError {
    #[error("Containment command signature is invalid")]
    InvalidSignature,
    #[error("Containment command is expired or has an invalid TTL")]
    ExpiredCommand,
    #[error("Containment command is not active")]
    InactiveCommand,
    #[error("Containment command nonce was already consumed")]
    Replay,
    #[error("Invalid containment target: {0}")]
    InvalidTarget(String),
    #[error("Requested enforcement action is not supported by this backend")]
    UnsupportedAction,
    #[error("Native enforcement command failed: {0}")]
    CommandFailed(String),
    #[error("Native enforcement command could not be started: {0}")]
    CommandStart(String),
}
