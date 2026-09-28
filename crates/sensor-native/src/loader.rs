#[cfg(target_os = "linux")]
use aya::{
    include_bytes_aligned,
    maps::RingBuf,
    programs::{KProbe, TracePoint},
    Bpf,
};
#[cfg(target_os = "linux")]
use aya_log::BpfLogger;
use tokio::sync::mpsc;
#[cfg(target_os = "linux")]
use tracing::{error, info};
use tracing::warn;

use crate::error::SensorNativeError;
use crate::normalizer::KernelEventNormalizer;
#[cfg(target_os = "linux")]
use security_control_plane_sensor_native_common::{
    KernelEventKind, KernelExecEvent, KernelNetEvent,
};

#[cfg(target_os = "linux")]
static SENSOR_BPF_BYTES: &[u8] = include_bytes_aligned!(
    "../../sensor-native-ebpf/target/bpfel-unknown-none/release/sensor-native-ebpf"
);

/// Loads eBPF programs and runs the ring buffer polling loop.
/// Sends normalized events to the channel returned by `start()`.
pub struct NativeSensorLoader {
    #[allow(dead_code)]
    normalizer: KernelEventNormalizer,
}

impl NativeSensorLoader {
    pub fn new(hostname: impl Into<String>) -> Self {
        Self {
            normalizer: KernelEventNormalizer::new(hostname),
        }
    }

    /// Loads eBPF programs, attaches tracepoints/kprobes, and returns a receiver
    /// that produces `SecurityEvent` items as the kernel emits them.
    ///
    /// This method REQUIRES root or CAP_BPF + CAP_PERFMON capabilities on Linux 5.15+.
    #[cfg(target_os = "linux")]
    pub async fn start(
        self,
    ) -> Result<mpsc::Receiver<security_control_plane_common::SecurityEvent>, SensorNativeError> {
        // Verify BTF availability before attempting to load
        if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
            return Err(SensorNativeError::BtfNotAvailable);
        }

        let (tx, rx) = mpsc::channel(8192);

        // Load eBPF object into kernel
        let mut bpf = Bpf::load(SENSOR_BPF_BYTES)
            .map_err(|e| SensorNativeError::BpfLoad(e.to_string()))?;

        // Set up eBPF logger (logs from eBPF programs → tracing)
        if let Err(e) = BpfLogger::init(&mut bpf) {
            warn!(error = %e, "Failed to init eBPF logger — kernel log messages will be silent");
        }

        // Attach tracepoint: execve
        {
            let prog: &mut TracePoint = bpf
                .program_mut("sys_enter_execve")
                .ok_or_else(|| SensorNativeError::Attachment {
                    program: "sys_enter_execve",
                    reason: "program not found in eBPF object".to_string(),
                })?
                .try_into()
                .map_err(|e: aya::programs::ProgramError| SensorNativeError::Attachment {
                    program: "sys_enter_execve",
                    reason: e.to_string(),
                })?;
            prog.load().map_err(|e| SensorNativeError::Attachment {
                program: "sys_enter_execve",
                reason: e.to_string(),
            })?;
            prog.attach("syscalls", "sys_enter_execve")
                .map_err(|e| SensorNativeError::Attachment {
                    program: "sys_enter_execve",
                    reason: e.to_string(),
                })?;
        }

        // Attach kprobes: connect, bind, accept4
        for prog_name in &["sys_connect", "sys_bind", "sys_accept4"] {
            let prog: &mut KProbe = bpf
                .program_mut(prog_name)
                .ok_or_else(|| SensorNativeError::Attachment {
                    program: prog_name,
                    reason: "program not found in eBPF object".to_string(),
                })?
                .try_into()
                .map_err(|e: aya::programs::ProgramError| SensorNativeError::Attachment {
                    program: prog_name,
                    reason: e.to_string(),
                })?;
            prog.load().map_err(|e| SensorNativeError::Attachment {
                program: prog_name,
                reason: e.to_string(),
            })?;
            prog.attach(prog_name, 0)
                .map_err(|e| SensorNativeError::Attachment {
                    program: prog_name,
                    reason: e.to_string(),
                })?;
        }

        info!("Native eBPF sensor loaded: execve + connect + bind + accept4 attached");

        let normalizer = self.normalizer;

        // Spawn the ring buffer polling task on a dedicated blocking thread
        // (ring buffer polling is synchronous and must not block the Tokio runtime)
        tokio::task::spawn_blocking(move || {
            let mut ring_buf = bpf
                .map_mut("EVENTS")
                .expect("EVENTS ring buffer map not found in eBPF object")
                .try_into::<RingBuf>()
                .expect("Failed to cast EVENTS to RingBuf");

            loop {
                // poll() with timeout 100ms — allows periodic shutdown check
                match ring_buf.next() {
                    Some(item) => {
                        let raw = item.as_ref();
                        if raw.len() < 4 {
                            continue;
                        }
                        let kind = u32::from_ne_bytes([raw[0], raw[1], raw[2], raw[3]]);

                        let security_event = match kind {
                            1 => {
                                // Execve
                                if raw.len() >= std::mem::size_of::<KernelExecEvent>() {
                                    let ev =
                                        unsafe { &*(raw.as_ptr() as *const KernelExecEvent) };
                                    Some(normalizer.normalize_exec(ev))
                                } else {
                                    None
                                }
                            }
                            2 | 3 | 4 => {
                                // Connect, Bind, Accept
                                if raw.len() >= std::mem::size_of::<KernelNetEvent>() {
                                    let ev =
                                        unsafe { &*(raw.as_ptr() as *const KernelNetEvent) };
                                    Some(normalizer.normalize_net(ev))
                                } else {
                                    None
                                }
                            }
                            _ => None,
                        };

                        if let Some(ev) = security_event {
                            if tx.blocking_send(ev).is_err() {
                                // Receiver dropped — shut down
                                break;
                            }
                        }
                    }
                    None => {
                        // No events — yield briefly to avoid busy-loop
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                }
            }

            // eBPF programs are automatically detached when `bpf` drops here
            info!("Native eBPF sensor polling loop terminated");
        });

        Ok(rx)
    }

    /// Non-Linux fallback loader: reports graceful error on platforms where eBPF is unavailable.
    #[cfg(not(target_os = "linux"))]
    pub async fn start(
        self,
    ) -> Result<mpsc::Receiver<security_control_plane_common::SecurityEvent>, SensorNativeError> {
        warn!("Native eBPF sensor requested on non-Linux platform: eBPF requires Linux 5.15+ LTS kernel");
        Err(SensorNativeError::BtfNotAvailable)
    }
}
