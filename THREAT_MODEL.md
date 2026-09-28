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

### Mitigations (Planned & Implemented)
- **Native Kernel eBPF Sensor (Phase 6)**: The in-tree eBPF sensor hooks directly into kernel tracepoints (`sys_enter_execve`) and kprobes (`sys_connect`, `sys_bind`, `sys_accept4`). Unprivileged applications cannot forge or suppress kernel-level syscall events. Even if an attacker compromises application middleware, the kernel probe emits ground-truth telemetry.
- **External sensor adapters** (Tetragon, Falco, Hubble) provide Kubernetes container runtime visibility outside the application container.
- **Anomaly detection on telemetry volume**: A sudden drop in event rate from an application that was previously active is itself a detection signal.

---

## 2. Agent & Control Channel Attack Surface

### Threat
The local enforcement agent is itself a target. An attacker who compromises the agent can:
- **Ignore containment commands**: Refuse to enforce session revocations or network blocks.
- **Exfiltrate signing keys**: Steal the Ed25519 private key and forge containment commands.
- **Replay old commands**: Re-execute expired containment actions.

### Current State & Architecture v3 Evolution
- Ed25519 signing is implemented with **mandatory TTLs** and **nonce-based replay protection**.
- The signing key is held strictly by the control plane; agents verify signatures using public keys only.
- **Native Enforcer (Phase 8)**: To eliminate reliance on in-process application agents, Phase 8 introduces OS-level containment (`nftables` DROP rules, XDP packet drops, SIGKILL). The control plane executes containment out-of-band at the kernel/firewall layer, meaning even a completely hijacked application process cannot refuse or bypass containment.

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
- **Standalone Mode (`corvus`, Phase 9)**: Implements single-binary zero-dependency deployment using an embedded SQLite durable sink and `MemoryHotState`. This provides persistent storage for events, incidents, and containment audit logs without external operational dependencies.
- **Distributed Mode**: In high-throughput deployments, Redis (hot sliding windows) and PostgreSQL (partitioned durable event store) can be enabled via feature flags.

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
- **Ring Buffer Drops**: The 256 KB eBPF ring buffer prioritizes kernel stability over guaranteed event delivery. Under extreme syscall pressure, if the ring buffer fills, events are safely dropped rather than blocking the kernel syscall execution path.
- **Privilege Requirements**: Loading requires root or `CAP_BPF + CAP_PERFMON` on Linux 5.15+ LTS with BTF (`/sys/kernel/btf/vmlinux`). Non-privileged environments gracefully fall back without crashing.

### Port Guardian (Phase 7)
- Processes binding to ephemeral ports could churn the port registry. Handled via sliding-window TTL eviction.

### External Sensor Adapters (Tetragon, Falco, Hubble)
- Rest-based adapters validate incoming JSON against strict schemas; corrupted or malformed external sensor payloads are rejected at the ingestion boundary.

---

## Scope Boundaries

This threat model covers the security control plane itself. It does **not** cover:
- Vulnerabilities in the applications being monitored.
- Infrastructure-level attacks (compromised Kubernetes control plane, hypervisor escapes).
- Physical access to the machines running the control plane.
- Supply chain attacks on the Rust toolchain or npm dependencies (though `cargo audit` and `npm audit` are recommended).

---

## Responsible Disclosure

If you discover a security vulnerability in this project, please follow the process described in [SECURITY.md](SECURITY.md) rather than opening a public issue.
