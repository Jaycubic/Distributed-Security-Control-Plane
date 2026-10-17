#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
    EbpfContext,
};
use aya_log_ebpf::info;
use security_control_plane_sensor_native_common::{
    KernelEventKind, KernelExecEvent, KernelNetEvent,
};

// Ring buffer: 256 KB capacity. Shared between all eBPF programs in this object.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(262144, 0);

/// Tracepoint on execve entry — fires on every process execution.
/// Prefer tracepoints over kprobes for syscall entry: they have stable ABI and lower overhead.
#[tracepoint]
pub fn sys_enter_execve(ctx: TracePointContext) -> i64 {
    match try_execve(ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // Never return error from eBPF — kernel ignores it
    }
}

fn try_execve(ctx: TracePointContext) -> Result<i64, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // sys_enter tracepoints start with an 8-byte common header, followed by the
    // syscall number and six arguments; execve filename is args[0] at byte 16.
    // SAFETY: offset 16 is the first u64 syscall argument in the sys_enter ABI.
    let filename_ptr: u64 = unsafe { ctx.read_at(16).map_err(|_| 1i64)? };

    let mut event = KernelExecEvent {
        kind: KernelEventKind::Execve as u32,
        pid,
        ppid: 0, // populated via PPID lookup in userspace from /proc/{pid}/status
        uid: (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32,
        gid: (bpf_get_current_uid_gid() >> 32) as u32,
        _pad: 0,
        comm: [0u8; 16],
        filename: [0u8; 256],
        // SAFETY: this eBPF helper is valid in tracepoint programs.
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
    };

    // Read comm (process name, max 15 chars)
    // SAFETY: the helper writes at most the size of the fixed event buffer.
    let _ = bpf_get_current_comm(&mut event.comm);

    // Read filename from user memory — safe because filename_ptr comes from user ABI
    // SAFETY: the helper validates the user pointer and bounds the copy to the buffer.
    let _ =
        unsafe { bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut event.filename) };

    // Write to ring buffer — if ring buffer is full, the event is dropped (not blocked)
    if let Some(mut entry) = EVENTS.reserve::<KernelExecEvent>(0) {
        // SAFETY: event has the exact type and size requested from reserve.
        unsafe { entry.write(event) };
        entry.submit(0);
    }

    Ok(0)
}

/// Degraded syscall-tracepoint fallback. The sockaddr remains user memory and is
/// therefore susceptible to TOCTOU races; the event must not be treated as authoritative.
#[tracepoint]
pub fn sys_enter_connect(ctx: TracePointContext) -> i64 {
    match try_connect(ctx) {
        Ok(ret) => ret,
        Err(_) => 0i64,
    }
}

fn try_connect(ctx: TracePointContext) -> Result<i64, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // With the 8-byte common header and 8-byte syscall number, connect's args[1]
    // sockaddr pointer is at byte 24.
    // SAFETY: offset 24 is connect(2)'s second argument in the sys_enter ABI.
    let sockaddr_ptr: u64 = unsafe { ctx.read_at(24).map_err(|_| 1i64)? };
    let sockaddr_ptr = sockaddr_ptr as *const u8;

    let mut sa_family: u16 = 0;
    // SAFETY: bpf_probe_read_user validates access to the user pointer.
    let _ = unsafe {
        aya_ebpf::helpers::bpf_probe_read_user(sockaddr_ptr as *const u16).map(|f| sa_family = f)
    };

    let mut event = KernelNetEvent {
        kind: KernelEventKind::Connect as u32,
        pid,
        ppid: 0,
        uid: (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32,
        gid: (bpf_get_current_uid_gid() >> 32) as u32,
        comm: [0u8; 16],
        sa_family,
        src_port: 0,
        dst_port: 0,
        _pad: [0u8; 2],
        src_ip4: [0u8; 4],
        dst_ip4: [0u8; 4],
        src_ip6: [0u8; 16],
        dst_ip6: [0u8; 16],
        // SAFETY: this eBPF helper is valid in tracepoint programs.
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
    };

    // SAFETY: the helper writes at most the size of the fixed event buffer.
    let _ = bpf_get_current_comm(&mut event.comm);

    // AF_INET = 2
    if sa_family == 2 {
        // sockaddr_in: [sa_family: u16][sin_port: u16][sin_addr: u32]
        // SAFETY: bpf_probe_read_user validates each read from the user pointer.
        let _ = unsafe {
            aya_ebpf::helpers::bpf_probe_read_user(sockaddr_ptr.add(2) as *const u16)
                .map(|p| event.dst_port = u16::from_be(p))
        };
        // SAFETY: bpf_probe_read_user validates each read from the user pointer.
        let _ = unsafe {
            aya_ebpf::helpers::bpf_probe_read_user(sockaddr_ptr.add(4) as *const [u8; 4])
                .map(|a| event.dst_ip4 = a)
        };
    }

    if let Some(mut entry) = EVENTS.reserve::<KernelNetEvent>(0) {
        // SAFETY: event has the exact type and size requested from reserve.
        unsafe { entry.write(event) };
        entry.submit(0);
    }

    Ok(0)
}

/// Degraded syscall-tracepoint fallback. The sockaddr remains user memory and is
/// therefore susceptible to TOCTOU races; the event must not be treated as authoritative.
#[tracepoint]
pub fn sys_enter_bind(ctx: TracePointContext) -> i64 {
    match try_bind(ctx) {
        Ok(ret) => ret,
        Err(_) => 0i64,
    }
}

fn try_bind(ctx: TracePointContext) -> Result<i64, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    // With the 8-byte common header and 8-byte syscall number, bind's args[1]
    // sockaddr pointer is at byte 24.
    // SAFETY: offset 24 is bind(2)'s second argument in the sys_enter ABI.
    let sockaddr_ptr: u64 = unsafe { ctx.read_at(24).map_err(|_| 1i64)? };
    let sockaddr_ptr = sockaddr_ptr as *const u8;

    let mut sa_family: u16 = 0;
    // SAFETY: bpf_probe_read_user validates access to the user pointer.
    let _ = unsafe {
        aya_ebpf::helpers::bpf_probe_read_user(sockaddr_ptr as *const u16).map(|f| sa_family = f)
    };

    let mut event = KernelNetEvent {
        kind: KernelEventKind::Bind as u32,
        pid,
        ppid: 0,
        uid: (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32,
        gid: (bpf_get_current_uid_gid() >> 32) as u32,
        comm: [0u8; 16],
        sa_family,
        src_port: 0,
        dst_port: 0,
        _pad: [0u8; 2],
        src_ip4: [0u8; 4],
        dst_ip4: [0u8; 4],
        src_ip6: [0u8; 16],
        dst_ip6: [0u8; 16],
        // SAFETY: this eBPF helper is valid in tracepoint programs.
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
    };

    // SAFETY: the helper writes at most the size of the fixed event buffer.
    let _ = bpf_get_current_comm(&mut event.comm);

    if sa_family == 2 {
        // SAFETY: bpf_probe_read_user validates each read from the user pointer.
        let _ = unsafe {
            aya_ebpf::helpers::bpf_probe_read_user(sockaddr_ptr.add(2) as *const u16)
                .map(|p| event.dst_port = u16::from_be(p))
        };
        // SAFETY: bpf_probe_read_user validates each read from the user pointer.
        let _ = unsafe {
            aya_ebpf::helpers::bpf_probe_read_user(sockaddr_ptr.add(4) as *const [u8; 4])
                .map(|a| event.dst_ip4 = a)
        };
    }

    if let Some(mut entry) = EVENTS.reserve::<KernelNetEvent>(0) {
        // SAFETY: event has the exact type and size requested from reserve.
        unsafe { entry.write(event) };
        entry.submit(0);
    }

    Ok(0)
}

/// Degraded tracepoint observation of accept attempts. The peer address is not
/// available at syscall entry, so this event is explicitly marked incomplete.
#[tracepoint]
pub fn sys_enter_accept4(_ctx: TracePointContext) -> i64 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let mut event = KernelNetEvent {
        kind: KernelEventKind::Accept as u32,
        pid,
        ppid: 0,
        uid: (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32,
        gid: (bpf_get_current_uid_gid() >> 32) as u32,
        comm: [0u8; 16],
        sa_family: 0,
        src_port: 0,
        dst_port: 0,
        _pad: [0u8; 2],
        src_ip4: [0u8; 4],
        dst_ip4: [0u8; 4],
        src_ip6: [0u8; 16],
        dst_ip6: [0u8; 16],
        // SAFETY: this eBPF helper is valid in tracepoint programs.
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
    };

    // SAFETY: the helper writes at most the size of the fixed event buffer.
    let _ = bpf_get_current_comm(&mut event.comm);

    if let Some(mut entry) = EVENTS.reserve::<KernelNetEvent>(0) {
        // SAFETY: event has the exact type and size requested from reserve.
        unsafe { entry.write(event) };
        entry.submit(0);
    }

    0i64
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
