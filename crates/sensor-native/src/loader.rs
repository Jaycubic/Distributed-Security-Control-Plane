#[cfg(target_os = "linux")]
use aya::{include_bytes_aligned, maps::RingBuf, programs::TracePoint, Bpf};
#[cfg(target_os = "linux")]
use aya_log::BpfLogger;
use tokio::sync::mpsc;
#[cfg(not(target_os = "linux"))]
use tracing::warn;
#[cfg(target_os = "linux")]
use tracing::{error, info, warn};

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

    /// Loads eBPF programs, attaches syscall tracepoints, and returns a receiver
    /// that produces `SecurityEvent` items as the kernel emits them.
    ///
    /// This method REQUIRES root or CAP_BPF + CAP_PERFMON capabilities on Linux 5.15+.
    #[cfg(target_os = "linux")]
    pub async fn start(
        self,
    ) -> Result<mpsc::Receiver<security_control_plane_common::SecurityEvent>, SensorNativeError>
    {
        // Verify BTF availability before attempting to load
        if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
            return Err(SensorNativeError::BtfNotAvailable);
        }

        let (tx, rx) = mpsc::channel(8192);

        // Load eBPF object into kernel
        let mut bpf =
            Bpf::load(SENSOR_BPF_BYTES).map_err(|e| SensorNativeError::BpfLoad(e.to_string()))?;

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
                .map_err(
                    |e: aya::programs::ProgramError| SensorNativeError::Attachment {
                        program: "sys_enter_execve",
                        reason: e.to_string(),
                    },
                )?;
            prog.load().map_err(|e| SensorNativeError::Attachment {
                program: "sys_enter_execve",
                reason: e.to_string(),
            })?;
            prog.attach("syscalls", "sys_enter_execve").map_err(|e| {
                SensorNativeError::Attachment {
                    program: "sys_enter_execve",
                    reason: e.to_string(),
                }
            })?;
        }

        // Use stable syscall tracepoints rather than architecture-dependent kprobe symbols.
        for (prog_name, tracepoint_name) in &[
            ("sys_enter_connect", "sys_enter_connect"),
            ("sys_enter_bind", "sys_enter_bind"),
            ("sys_enter_accept4", "sys_enter_accept4"),
        ] {
            let prog: &mut TracePoint = bpf
                .program_mut(prog_name)
                .ok_or_else(|| SensorNativeError::Attachment {
                    program: prog_name,
                    reason: "program not found in eBPF object".to_string(),
                })?
                .try_into()
                .map_err(
                    |e: aya::programs::ProgramError| SensorNativeError::Attachment {
                        program: prog_name,
                        reason: e.to_string(),
                    },
                )?;
            prog.load().map_err(|e| SensorNativeError::Attachment {
                program: prog_name,
                reason: e.to_string(),
            })?;
            prog.attach("syscalls", tracepoint_name).map_err(|e| {
                SensorNativeError::Attachment {
                    program: prog_name,
                    reason: e.to_string(),
                }
            })?;
        }

        info!("Native eBPF sensor loaded with degraded syscall-tracepoint capture");
        let normalizer = self.normalizer;

        let ring_buf = bpf
            .take_map("EVENTS")
            .ok_or_else(|| SensorNativeError::RingBuf("EVENTS map not found".to_string()))?
            .try_into::<RingBuf<_>>()
            .map_err(|e| SensorNativeError::RingBuf(e.to_string()))?;
        let ring_buf = tokio::io::unix::AsyncFd::new(ring_buf)
            .map_err(|e| SensorNativeError::RingBuf(e.to_string()))?;

        // RingBuf is registered with epoll through AsyncFd, avoiding the former
        // sleep/poll loop while keeping its synchronous API off the Tokio runtime.
        tokio::spawn(async move {
            let _bpf = bpf;
            loop {
                let mut readiness = match ring_buf.readable().await {
                    Ok(readiness) => readiness,
                    Err(e) => {
                        error!(error = %e, "Failed waiting for native sensor ring buffer");
                        break;
                    }
                };

                let mut receiver_closed = false;
                loop {
                    let security_event = {
                        let ring_buf = readiness.get_inner_mut();
                        let Some(item) = ring_buf.next() else {
                            break;
                        };
                        normalize_ringbuf_item(item.as_ref(), &normalizer)
                    };

                    match security_event {
                        Ok(Some(event)) => {
                            if tx.send(event).await.is_err() {
                                receiver_closed = true;
                                break;
                            }
                        }

                        Ok(None) => {}
                        Err(reason) => {
                            warn!(reason = %reason, "Discarding malformed native sensor event")
                        }
                    }
                }

                readiness.clear_ready();
                if receiver_closed {
                    break;
                }
            }

            // eBPF programs are automatically detached when `bpf` drops here
            info!("Native eBPF sensor consumer terminated");
        });

        Ok(rx)
    }

    #[cfg(target_os = "linux")]
    fn normalize_ringbuf_item(
        raw: &[u8],
        normalizer: &KernelEventNormalizer,
    ) -> Result<Option<security_control_plane_common::SecurityEvent>, String> {
        if raw.len() < std::mem::size_of::<u32>() {
            return Err(format!("event header is truncated: {} bytes", raw.len()));
        }
        let kind = u32::from_ne_bytes([raw[0], raw[1], raw[2], raw[3]]);
        match kind {
            1 if raw.len() >= std::mem::size_of::<KernelExecEvent>() => {
                // SAFETY: Aya's ring buffer records are 8-byte aligned; the checked
                // length covers the complete POD event layout shared with eBPF.
                let event = unsafe { &*(raw.as_ptr() as *const KernelExecEvent) };
                Ok(Some(normalizer.normalize_exec(event)))
            }
            2..=4 if raw.len() >= std::mem::size_of::<KernelNetEvent>() => {
                // SAFETY: Aya's ring buffer records are 8-byte aligned; the checked
                // length covers the complete POD event layout shared with eBPF.
                let event = unsafe { &*(raw.as_ptr() as *const KernelNetEvent) };
                Ok(Some(normalizer.normalize_net(event)))
            }
            1..=4 => Err(format!(
                "event kind {kind} has invalid length: {} bytes",
                raw.len()
            )),
            _ => Ok(None),
        }
    }

    /// Non-Linux fallback loader: reports graceful error on platforms where eBPF is unavailable.
    #[cfg(not(target_os = "linux"))]
    pub async fn start(
        self,
    ) -> Result<mpsc::Receiver<security_control_plane_common::SecurityEvent>, SensorNativeError>
    {
        warn!("Native eBPF sensor requested on non-Linux platform: eBPF requires Linux 5.15+ LTS kernel");
        Err(SensorNativeError::BtfNotAvailable)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::NativeSensorLoader;
    use std::time::Duration;

    #[tokio::test]
    #[ignore = "requires Linux BPF tracepoint privileges and a built eBPF object"]
    async fn test_tracepoint_fallback_attaches_connect_bind_accept() {
        let receiver = NativeSensorLoader::new("phase6-lab").start().await;
        assert!(
            receiver.is_ok(),
            "tracepoint fallback failed to attach: {:?}",
            receiver.err()
        );
    }

    #[tokio::test]
    #[ignore = "requires Linux BPF tracepoint privileges and a built eBPF object"]
    async fn test_ringbuf_consumer_wakes_on_event() {
        let mut receiver = match NativeSensorLoader::new("phase6-lab").start().await {
            Ok(receiver) => receiver,
            Err(error) => panic!("tracepoint fallback failed to start: {error}"),
        };

        let child_path = match std::env::current_exe() {
            Ok(path) => path,
            Err(error) => panic!("failed to locate the test process executable: {error}"),
        };
        let child = tokio::process::Command::new(&child_path)
            .arg("--list")
            .output()
            .await;
        assert!(child.is_ok(), "known child process failed: {child:?}");

        let event = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(event) = receiver.recv().await {
                    if event.event_type == "kernel.execve"
                        && event.metadata.get("filename").and_then(|v| v.as_str())
                            == child_path.to_str()
                    {
                        return event;
                    }
                } else {
                    panic!("native sensor event channel closed before child event arrived");
                }
            }
        })
        .await;

        assert!(
            event.is_ok(),
            "ring-buffer consumer did not wake on child event"
        );
    }
}
