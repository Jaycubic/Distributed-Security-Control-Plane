#![cfg_attr(not(feature = "user"), no_std)]

/// Discriminant for the kernel event type, transmitted as u32 in the ring buffer.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelEventKind {
    Execve = 1,
    Connect = 2,
    Bind = 3,
    Accept = 4,
}

impl KernelEventKind {
    /// Parse u32 discriminator to KernelEventKind
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            1 => Some(KernelEventKind::Execve),
            2 => Some(KernelEventKind::Connect),
            3 => Some(KernelEventKind::Bind),
            4 => Some(KernelEventKind::Accept),
            _ => None,
        }
    }
}

/// Execve event: process execution detected via tracepoint/syscalls/sys_enter_execve.
/// Total size: 4 + 4 + 4 + 4 + 4 + 4 + 16 + 256 + 8 = 304 bytes
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KernelExecEvent {
    pub kind: u32,           // KernelEventKind::Execve as u32
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub _pad: u32,           // explicit padding for alignment
    pub comm: [u8; 16],      // task comm (short name, max 15 chars + null)
    pub filename: [u8; 256], // full path to executed binary
    pub timestamp_ns: u64,   // ktime_get_ns()
}

/// Network connect/bind/accept event.
/// Total size: 4 + 4 + 4 + 4 + 4 + 2 + 2 + 2 + 2 + 4 + 4 + 16 + 16 + 8 + 16 + 8 = 108 bytes, pad to 128
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KernelNetEvent {
    pub kind: u32,           // KernelEventKind as u32
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: [u8; 16],
    pub sa_family: u16,      // AF_INET = 2, AF_INET6 = 10
    pub src_port: u16,       // host byte order
    pub dst_port: u16,       // host byte order
    pub _pad: [u8; 2],
    pub src_ip4: [u8; 4],    // IPv4 in network byte order (only valid when sa_family == 2)
    pub dst_ip4: [u8; 4],
    pub src_ip6: [u8; 16],   // IPv6 (only valid when sa_family == 10)
    pub dst_ip6: [u8; 16],
    pub timestamp_ns: u64,
}

// Safety: These types are plain-old-data with no padding gaps when laid out as declared.
// Verified by compile-time size assertions in the userspace crate.
#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for KernelExecEvent {}
#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for KernelNetEvent {}
