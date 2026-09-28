#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_ns, bpf_probe_read_user_str_bytes,
    },
    macros::{kprobe, map, tracepoint},
    maps::RingBuf,
    programs::{ProbeContext, TracePointContext},
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

    // Read the filename pointer from tracepoint args at offset 8 (kernel abi: filename)
    let filename_ptr: u64 = unsafe { ctx.read_at(8).map_err(|_| 1i64)? };

    let mut event = KernelExecEvent {
        kind: KernelEventKind::Execve as u32,
        pid,
        ppid: 0, // populated via PPID lookup in userspace from /proc/{pid}/status
        uid: (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32,
        gid: (bpf_get_current_uid_gid() >> 32) as u32,
        _pad: 0,
        comm: [0u8; 16],
        filename: [0u8; 256],
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
    };

    // Read comm (process name, max 15 chars)
    let _ = bpf_get_current_comm(&mut event.comm);

    // Read filename from user memory — safe because filename_ptr comes from user ABI
    let _ = unsafe {
        bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut event.filename)
    };

    // Write to ring buffer — if ring buffer is full, the event is dropped (not blocked)
    if let Some(mut entry) = EVENTS.reserve::<KernelExecEvent>(0) {
        unsafe { entry.write(event) };
        entry.submit(0);
    }

    Ok(0)
}

/// kprobe on sys_connect: fires when a process initiates a network connection.
/// Used for detecting outbound connections from server processes.
#[kprobe]
pub fn sys_connect(ctx: ProbeContext) -> u32 {
    match try_connect(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_connect(ctx: ProbeContext) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // ctx.arg(1) = struct sockaddr __user * uservaddr
    let sockaddr_ptr: *const u8 = unsafe { ctx.arg(1).ok_or(1u32)? };

    let mut sa_family: u16 = 0;
    // Read sa_family (first 2 bytes of sockaddr)
    let _ = unsafe {
        aya_ebpf::helpers::bpf_probe_read_user(sockaddr_ptr as *const u16)
            .map(|f| sa_family = f)
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
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
    };

    let _ = bpf_get_current_comm(&mut event.comm);

    // AF_INET = 2
    if sa_family == 2 {
        // sockaddr_in: [sa_family: u16][sin_port: u16][sin_addr: u32]
        let _ = unsafe {
            aya_ebpf::helpers::bpf_probe_read_user(sockaddr_ptr.add(2) as *const u16)
                .map(|p| event.dst_port = u16::from_be(p))
        };
        let _ = unsafe {
            aya_ebpf::helpers::bpf_probe_read_user(sockaddr_ptr.add(4) as *const [u8; 4])
                .map(|a| event.dst_ip4 = a)
        };
    }

    if let Some(mut entry) = EVENTS.reserve::<KernelNetEvent>(0) {
        unsafe { entry.write(event) };
        entry.submit(0);
    }

    Ok(0)
}

/// kprobe on sys_bind: fires when a process binds to a port.
/// Critical for Port Guardian (Phase 7): records which process owns which port.
#[kprobe]
pub fn sys_bind(ctx: ProbeContext) -> u32 {
    match try_bind(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_bind(ctx: ProbeContext) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let sockaddr_ptr: *const u8 = unsafe { ctx.arg(1).ok_or(1u32)? };

    let mut sa_family: u16 = 0;
    let _ = unsafe {
        aya_ebpf::helpers::bpf_probe_read_user(sockaddr_ptr as *const u16)
            .map(|f| sa_family = f)
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
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
    };

    let _ = bpf_get_current_comm(&mut event.comm);

    if sa_family == 2 {
        let _ = unsafe {
            aya_ebpf::helpers::bpf_probe_read_user(sockaddr_ptr.add(2) as *const u16)
                .map(|p| event.dst_port = u16::from_be(p))
        };
        let _ = unsafe {
            aya_ebpf::helpers::bpf_probe_read_user(sockaddr_ptr.add(4) as *const [u8; 4])
                .map(|a| event.dst_ip4 = a)
        };
    }

    if let Some(mut entry) = EVENTS.reserve::<KernelNetEvent>(0) {
        unsafe { entry.write(event) };
        entry.submit(0);
    }

    Ok(0)
}

/// kprobe on sys_accept4: fires when a listening process accepts a new connection.
#[kprobe]
pub fn sys_accept4(ctx: ProbeContext) -> u32 {
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
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
    };

    let _ = bpf_get_current_comm(&mut event.comm);

    if let Some(mut entry) = EVENTS.reserve::<KernelNetEvent>(0) {
        unsafe { entry.write(event) };
        entry.submit(0);
    }

    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
