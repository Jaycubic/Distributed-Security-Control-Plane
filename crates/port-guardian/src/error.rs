use security_control_plane_engine::HotStateError;

#[derive(Debug, thiserror::Error)]
pub enum PortGuardianError {
    #[error("Hot-state operation failed: {0}")]
    HotState(#[from] HotStateError),
}
