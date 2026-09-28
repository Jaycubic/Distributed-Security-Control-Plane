pub mod error;
pub mod loader;
pub mod normalizer;
pub mod process_info;
pub mod producer;

pub use error::SensorNativeError;
pub use loader::NativeSensorLoader;
pub use normalizer::KernelEventNormalizer;
pub use producer::NativeSensorProducer;

#[cfg(test)]
mod tests {
    use super::normalizer::{null_terminated_str, KernelEventNormalizer};
    use security_control_plane_common::{SensorType, Severity};
    use security_control_plane_sensor_native_common::KernelExecEvent;

    fn make_exec_event(filename: &str, uid: u32, pid: u32) -> KernelExecEvent {
        let mut ev = KernelExecEvent {
            kind: 1,
            pid,
            ppid: 0,
            uid,
            gid: 1000,
            _pad: 0,
            comm: [0u8; 16],
            filename: [0u8; 256],
            timestamp_ns: 0,
        };
        let bytes = filename.as_bytes();
        let len = bytes.len().min(255);
        ev.filename[..len].copy_from_slice(&bytes[..len]);
        let comm_bytes = b"bash";
        let comm_len = comm_bytes.len().min(15);
        ev.comm[..comm_len].copy_from_slice(&comm_bytes[..comm_len]);
        ev
    }

    #[test]
    fn test_null_terminated_str_normal() {
        let mut buf = [0u8; 16];
        buf[..5].copy_from_slice(b"nginx");
        assert_eq!(null_terminated_str(&buf), "nginx");
    }

    #[test]
    fn test_null_terminated_str_no_null() {
        let buf = [b'a'; 16];
        assert_eq!(null_terminated_str(&buf).len(), 16);
    }

    #[test]
    fn test_exec_normalization_bash_root_critical() {
        let normalizer = KernelEventNormalizer::new("test-host");
        let ev = make_exec_event("/bin/bash", 0, 1234);
        let event = normalizer.normalize_exec(&ev);
        assert_eq!(event.app_id, "test-host");
        assert_eq!(event.event_type, "kernel.execve");
        assert_eq!(event.source.sensor.sensor_type, SensorType::NativeSensor);
        assert_eq!(event.severity, Severity::Critical); // bash as root = Critical
        assert!(event.is_security_significant);
    }

    #[test]
    fn test_exec_normalization_bash_non_root_medium() {
        let normalizer = KernelEventNormalizer::new("test-host");
        let ev = make_exec_event("/bin/bash", 1000, 5678);
        let event = normalizer.normalize_exec(&ev);
        assert_eq!(event.severity, Severity::Medium); // bash as non-root = Medium
    }

    #[test]
    fn test_exec_normalization_nginx_low() {
        let normalizer = KernelEventNormalizer::new("test-host");
        let ev = make_exec_event("/usr/sbin/nginx", 33, 9999);
        let event = normalizer.normalize_exec(&ev);
        assert_eq!(event.severity, Severity::Low);
        assert!(!event.is_security_significant);
    }

    #[test]
    fn test_metadata_fields_present() {
        let normalizer = KernelEventNormalizer::new("test-host");
        let ev = make_exec_event("/usr/bin/curl", 1000, 1111);
        let event = normalizer.normalize_exec(&ev);
        assert!(event.metadata.contains_key("uid"));
        assert!(event.metadata.contains_key("filename"));
        assert!(event.metadata.contains_key("comm"));
    }
}
