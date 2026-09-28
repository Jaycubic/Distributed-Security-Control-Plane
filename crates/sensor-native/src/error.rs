#[derive(Debug, thiserror::Error)]
pub enum SensorNativeError {
    #[error("eBPF object load failed: {0}")]
    BpfLoad(String),
    #[error("Program attachment failed for '{program}': {reason}")]
    Attachment {
        program: &'static str,
        reason: String,
    },
    #[error("Ring buffer poll error: {0}")]
    RingBuf(String),
    #[error("Event normalization error: {0}")]
    Normalization(String),
    #[error("Kernel requires BTF support. Verify /sys/kernel/btf/vmlinux exists and kernel >= 5.15")]
    BtfNotAvailable,
    #[error("Insufficient capabilities. Requires CAP_BPF + CAP_PERFMON or root.")]
    InsufficientCapabilities,
}
