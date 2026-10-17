# Phase 6A Foundation Audit

## Status

**Blocked pending a Linux lab run.** This audit records source-level findings only. The current development host is Windows; no supported Linux kernel, BTF, tracefs, BPF LSM, or eBPF runtime is available here. No kernel attachment, sample event, or CPU measurement is claimed.

Per Architecture v4, do not begin Phase 6B until the real-kernel results below are completed.

## Static review

| Hook | Current implementation | Static finding | Kernel version / attach result / sample event |
|---|---|---|---|
| `syscalls:sys_enter_execve` | Tracepoint | Reads the filename through a user-space pointer; TOCTOU-vulnerable | Not run |
| `sys_connect` | Kprobe | Architecture-dependent symbol; reads user-space sockaddr | Not run |
| `sys_bind` | Kprobe | Architecture-dependent symbol; reads user-space sockaddr | Not run |
| `sys_accept4` | Kprobe | Records no accepted peer address | Not run |

The loader currently drains `RingBuf::next()` and sleeps for 1 ms when empty. Phase 6A still needs to replace this with fd readiness notification. The kernel program's ring-buffer reserve failures are not counted and no health event reports loss.

## Required Linux lab record

Complete this section on at least one Linux 5.15+ lab host before Phase 6B:

| Field | Result |
|---|---|
| Distro and release | Pending |
| Kernel release | Pending |
| BTF available | Pending |
| Hook attach results | Pending |
| Exec sample (known child) | Pending |
| Connect sample (destination) | Pending |
| Bind sample (port) | Pending |
| Accept sample (peer address) | Pending |
| Idle sensor CPU under no load | Pending |
| Ring-buffer consumer wake test | Pending |

Use [`tools/lab/phase6_smoke.sh`](../../tools/lab/phase6_smoke.sh) while the sensor runs. Record a separate result for every hook; do not mark an attachment successful based only on successful object loading.
