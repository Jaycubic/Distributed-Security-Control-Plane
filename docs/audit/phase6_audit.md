# Phase 6A Foundation Audit

## Status

**Blocked pending a Linux lab run.** This audit records source-level findings only. The current development host is Windows; no supported Linux kernel, BTF, tracefs, BPF LSM, or eBPF runtime is available here. No kernel attachment, sample event, or CPU measurement is claimed.

Per Architecture v4, do not begin Phase 6B until the real-kernel results below are completed.

## Static review

The local implementation now uses syscall tracepoints for `execve`, `connect`,
`bind`, and `accept4`; the architecture-dependent `sys_connect`, `sys_bind`,
and `sys_accept4` kprobe attachments have been removed. The userspace consumer
waits on the ring-buffer fd through Tokio `AsyncFd` rather than polling with a
1 ms sleep. All four event types are labeled `tracepoint_degraded`, and the
normalizer records `toctou_vulnerable` for exec/connect/bind and
`no_inbound_accept` for accept attempts. These source changes are not a claim
that any hook has been verified on a live kernel.

The tracepoint context offsets account for the 8-byte common event header and
the 8-byte syscall number: `execve` reads `args[0]` at offset 16, while
`connect` and `bind` read `args[1]` at offset 24.

| Hook | Current implementation | Static finding | Kernel version / attach result / sample event |
|---|---|---|---|
| `syscalls:sys_enter_execve` | Tracepoint | Reads the filename through a user-space pointer; TOCTOU-vulnerable, labeled degraded | Not run |
| `syscalls:sys_enter_connect` | Tracepoint | Reads user-space sockaddr; TOCTOU-vulnerable, labeled degraded | Not run |
| `syscalls:sys_enter_bind` | Tracepoint | Reads user-space sockaddr; TOCTOU-vulnerable, labeled degraded | Not run |
| `syscalls:sys_enter_accept4` | Tracepoint | Observes accept attempts only; peer address unavailable and labeled `no_inbound_accept` | Not run |

The loader waits for ring-buffer fd readiness through `AsyncFd`. Ring-buffer reserve
failures are not yet counted and no health event reports loss; this remains for
Phase 6C.

## Required Linux lab record

Complete this section on at least one Linux 5.15+ lab host before Phase 6B:

| Field | Result |
|---|---|
| Distro and release | Ubuntu 22.04.5 LTS (read-only host probe; no hooks tested) |
| Kernel release | Linux 5.15.0-168-generic x86_64 (read-only host probe) |
| Host role | Production server; no eBPF programs were attached |
| BTF available | Present (`/sys/kernel/btf/vmlinux` readable) |
| `CONFIG_BPF_LSM` | `y` in `/boot/config-5.15.0-168-generic` |
| `bpf` in active LSM list | No; active list did not include `bpf` |
| eBPF toolchain | `bpf-linker` build blocked: `llvm-config` unavailable |
| Hook attach results | Not run |
| Exec sample (known child) | Pending |
| Connect sample (destination) | Pending |
| Bind sample (port) | Pending |
| Accept sample (peer address) | Pending |
| Idle sensor CPU under no load | Pending |
| Ring-buffer consumer wake test | Pending |

Use [`tools/lab/phase6_smoke.sh`](../../tools/lab/phase6_smoke.sh) while the sensor runs. Record a separate result for every hook; do not mark an attachment successful based only on successful object loading.

The production host was used only for read-only environment diagnostics and was
not treated as a kernel test lab. Do not enable BPF LSM, attach probes, change
boot configuration, or reboot it for this audit.
