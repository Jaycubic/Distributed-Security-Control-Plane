# Threat Model & Known Limitations

This document describes the known threats, attack surfaces, and unsolved problems in the Distributed Security Control Plane. These are acknowledged limitations, not solved problems — documenting them is intentional and part of responsible security engineering.

---

## 1. Telemetry Integrity

### Threat
A compromised application can forge, replay, or suppress its own security telemetry. Since the emitter runs inside the application process, an attacker who gains code execution can:
- **Forge events**: Inject false telemetry to trigger containment against innocent users or services.
- **Suppress events**: Disable the emitter or drop events to hide malicious activity.
- **Replay events**: Re-send old events to pollute the correlation graph or trigger false incidents.

### Current State
The control plane currently **trusts all emitters**. There is no authentication, signing, or integrity verification on inbound telemetry from application middleware.

### Mitigations (Implemented & Remaining)
- **Native Kernel eBPF Sensor (degraded fallback prototype)**: The current implementation uses syscall tracepoints and reads user-space exec filenames and connect/bind sockaddr pointers. Events are labeled `tracepoint_degraded` and carry `toctou_vulnerable`; accept-attempt events carry `no_inbound_accept` because the peer address is unavailable at syscall entry. The ring-buffer consumer now waits for fd readiness, but reserve failures are not counted, and process attribution still uses PID plus racy userspace `/proc` reads.
- **V4 direction, not yet implemented**: Architecture-dependent kprobes have been removed, but Phase 6A remains blocked pending real-kernel attach, sample-event, ring-buffer wake, and CPU results. Phase 6B moves primary capture to LSM hooks where arguments are in kernel memory, with stable process identity. The tracepoint path remains explicitly degraded. LSM-BPF requires `CONFIG_BPF_LSM` and `bpf` in the active LSM list.
- **External sensor adapters** (Tetragon, Falco, Hubble) provide Kubernetes container runtime visibility outside the application container.
- **Remaining risk**: Inbound telemetry is not authenticated or signed by the control plane. A compromised or spoofed emitter can still forge or replay events; deployment-level authentication and network isolation are required. Syscall monitoring also misses activity performed exclusively through io_uring; V4 plans to report this blind spot rather than claim complete coverage.

---

## 2. Agent & Control Channel Attack Surface

### Threat
The local enforcement agent is itself a target. An attacker who compromises the agent can:
- **Ignore containment commands**: Refuse to enforce session revocations or network blocks.
- **Exfiltrate signing keys**: Steal the Ed25519 private key and forge containment commands.
- **Replay old commands**: Re-execute expired containment actions.

### Current State & Architecture v4 Evolution
- Ed25519-signed containment commands include **mandatory TTLs** and replay identifiers.
- **Native Enforcer (V3 Phase 8)** is opt-in (`NATIVE_ENFORCER=true`) and executes userspace actions after the detection event. It is post-hoc and cannot prevent the original exec/connect syscall.
- The current backend uses `kill -9` by PID and modifies a shared nftables structure; PID reuse can target the wrong process and broad rollback can disturb unrelated firewall state. Process termination is irreversible. Keep the enforcer disabled in production until V4 phases 8A–8C's decisions, bouncers, pidfd, expiry, reconciliation, and lockout-prevention requirements are met.
- **Synchronous LSM deny (V4 Phase 8B)** is not implemented. V4 requires audit mode first, explicit operator promotion, protected process/cgroup exclusions, expiry cleanup, fail-open behavior, and automatic detach when the agent exits.

---

## 3. Identity Resolution Errors

### Threat
The identity resolution layer merges heterogeneous identifiers (IP addresses, session tokens, user IDs, container IDs, PIDs) into unified entity nodes. Errors in this merging can have security consequences:
- **False merge**: Two unrelated actors are merged into one entity. Containment actions intended for one affect both.
- **False split**: One actor appears as multiple entities. Multi-stage attack sequences go undetected.

### Current State
- Entity resolution uses deterministic rules: same IP + same session token = same entity. Same user ID across applications = same entity.
- There is **no confidence scoring** on identity merges yet.
- Operator inspection via the live context graph API allows forensic validation.

---

## 4. State Durability & Single-Node Resilience

### Threat
- **State loss on restart**: A restart losing in-memory correlation graph or rate windows allows an attacker to reset detection counters.
- **Operational overhead**: Requiring external distributed databases (PostgreSQL, Redis) for small or single-server deployments introduces operational points of failure.

### Architecture v3 Resolution
- **Standalone Mode (`corvus`, Phase 9)**: Uses an embedded SQLite durable sink and `MemoryHotState` for events, incidents, and containment records, without external database services.
- **Distributed Mode**: The `distributed` feature supports Redis hot state. Durable PostgreSQL storage is not implemented; the distributed durable sink is currently in-memory.

---

## 5. Detection Evasion & Detect-and-Respond Latency

### Threat
- **Slow-play**: Staying below rate thresholds by spacing requests just outside the detection window.
- **The Out-of-Band Window**: Because the control plane sits out-of-band to preserve zero request-path coupling, the system cannot prevent the first $N$ malicious requests inline. Containment takes effect after detection-to-containment latency.

### Current State
- Detection rules are deterministic and threshold-based.
- **Advisory LLM Reasoning (Phase 11)**: Frozen until the native kernel, port, and enforcement foundation (Phases 6–10) is fully solidified. When activated in Mode B, it assists with ambiguous multi-stage reasoning, strictly bounded by the deterministic policy gate (`DENY > ALLOW`).

---

## 6. Sensor-Specific & eBPF Kernel Risks

### Native eBPF Sensor (Phase 6)
- **Kernel Verifier Safety**: All in-tree eBPF programs are verified at load time by the Linux kernel verifier, guaranteeing termination, memory safety, and no panics.
- **Ring Buffer Drops**: The 256 KB eBPF ring buffer prioritizes kernel stability over guaranteed event delivery. The userspace consumer waits for fd readiness, but reserve failures still are not counted or surfaced as health events. This remains a known telemetry-loss risk pending Phase 6C.
- **Privilege Requirements**: Loading requires root or `CAP_BPF + CAP_PERFMON` on Linux 5.15+ LTS with BTF (`/sys/kernel/btf/vmlinux`). Non-privileged environments gracefully fall back without crashing.

### Port Guardian (V3 Phase 7)
- The current detector relies on local bind/connect/accept events and registered ports. Outbound `connect` is not inbound scan telemetry, and a SYN scan against closed ports will not complete an `accept`; the current phase cannot detect that common scan type.
- Bind events miss services already listening when the sensor starts. There is no candidate/approve/protect service lifecycle, and filename-only severity is easy to evade through renaming.
- V4 phases 7A–7C replace this with host enrollment, service discovery/reconciliation and approval, and aggregated ingress SYN observation. Until then, scan detections are limited and should not be treated as comprehensive.

### Packet Inspection (Phase 10, partial)
- Portable HTTP, DNS, and TLS payload parsing and an ingestion endpoint are implemented. The bounded TCP reassembly component is not connected to a live packet stream.
- There is no AF_XDP socket, XDP redirect, or live network capture path. Submitted payloads remain untrusted input and must be bounded and validated at the ingestion boundary.

### Host and service onboarding (V4 planned)
- V3 has no pending-then-approved host enrollment or authenticated sensor-post protocol. It also has no service proposal/approval workflow. Until implemented, deployments must not treat an observed host/listener as approved or authenticated.

### Residual kernel risks (V4)
- A privileged/root attacker can detach or blind eBPF programs. BPF/module-load monitoring can improve observability but cannot guarantee sensor integrity.
- If LSM-BPF is unavailable, syscall tracepoints remain TOCTOU-vulnerable and must be explicitly labeled degraded.
- io_uring can bypass syscall-level observation. Health reporting and `corvus doctor` are planned coverage signals, not mitigations that eliminate the blind spot.

### External Sensor Adapters (Tetragon, Falco, Hubble)
- Rest-based adapters validate incoming JSON against strict schemas; corrupted or malformed external sensor payloads are rejected at the ingestion boundary.

---

## Scope Boundaries

This threat model covers the security control plane itself. It does **not** cover:
- Vulnerabilities in the applications being monitored.
- Infrastructure-level attacks (compromised Kubernetes control plane, hypervisor escapes).
- Physical access to the machines running the control plane.
- Supply chain attacks on the Rust toolchain or npm dependencies (though `cargo audit` and `npm audit` are recommended).
- Network-level authentication/TLS and operator access control; these must be provided by a trusted deployment boundary.

---

## Responsible Disclosure

If you discover a security vulnerability in this project, please follow the process described in [SECURITY.md](SECURITY.md) rather than opening a public issue.
