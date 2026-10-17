# Distributed Security Control Plane

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Rust: 1.80+](https://img.shields.io/badge/Rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)
[![React: 18.3](https://img.shields.io/badge/Frontend-React_%2B_TypeScript-61dafb.svg)](https://react.dev/)
[![Architecture: Out--of--Band](https://img.shields.io/badge/Architecture-Out--of--Band_Control_Plane-emerald.svg)](#core-architectural-invariant)

> **An open-source, out-of-band security control plane that asynchronously collects security telemetry from applications and runtime sensors, resolves identity, correlates activity across services, detects abnormal behavior, and coordinates graduated containment — without placing security analysis on the synchronous application request path.**

**Core idea:** security should observe and act on applications without becoming a dependency of their normal request path.

[Architecture](#system-architecture) · [Trade-offs](#design-trade-offs) · [Quickstart](#quickstart--local-setup) · [Roadmap](#12-phase-development-roadmap) · [Threat Model](THREAT_MODEL.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

---

## Why This Project?

Security signals are distributed across application logs, runtime syscall alerts, kernel process telemetry, and network flow data. Looking at each stream independently misses relationships: a routine login on App A, an API call on App B, and a mass data export on App C only look like one coordinated attack when you correlate across all three.

Existing tools tend to specialize in one layer. This project explores whether a dedicated control plane sitting *beside* applications — not *between* them and their clients — can fuse signals from application middleware, eBPF kernel probes (Tetragon), runtime syscall rules (Falco), and network flows (Hubble) into a unified security context, and then act on it through cryptographically signed, time-bounded, reversible containment commands.

The pieces that make this more than another SIEM are:
- **Capability-based policy model** where `DENY` always beats `ALLOW`, inspired by Deno's permission system.
- **Ed25519-signed containment commands** with mandatory TTLs and replay protection, so enforcement actions are auditable and automatically expire.
- **Graduated, reversible responses** — from session revocation to service isolation, each with explicit rollback.
- **Cross-application identity resolution** that stitches together IPs, session tokens, user IDs, container IDs, and PIDs into a unified entity graph.

```text
APPLICATIONS
    │
    │ asynchronous telemetry
    ▼
SECURITY CONTROL PLANE
    │
    ├── Identity Resolution
    ├── Cross-Application Correlation
    ├── Deterministic Detection
    ├── Risk & Policy
    ├── Incident Management
    └── Containment Coordination
            │
            │ signed command (Ed25519, TTL-bounded)
            ▼
       LOCAL AGENT
            │
            ▼
        ENFORCEMENT
```

---

## Design Trade-offs

This architecture is **detect-and-respond**, not **prevent**. Because security analysis runs out-of-band, the system cannot block the first malicious request inline. An attacker gets some number of requests through before a containment command lands at the local agent. The number that matters is **detection-to-containment latency** — the time between ingesting a suspicious event and the agent enforcing a response.

What you get in return is **zero request-path coupling**: normal application traffic never waits on security analysis, correlation, or the controller. If the control plane goes down, applications continue serving traffic unaffected, and local agents buffer telemetry and continue enforcing cached policies.

This is an explicit trade-off, not a universal improvement over inline security. Inline gateways can block known-bad requests before they reach the application; this system cannot. For threats that require correlating signals across multiple services, time windows, and runtime layers — which inline gateways cannot easily do — the out-of-band model is stronger.

### Core Architectural Invariant
> *"Normal application requests must never wait for security ingestion, correlation, detection, or the security controller."*

---

## What This Is and Isn't

| | This Project | Inline WAF / API Gateway | Falco / Tetragon (standalone) | Wazuh / Elastic Security |
| :--- | :--- | :--- | :--- | :--- |
| **Architecture** | Out-of-band control plane | Inline request path | Per-node agent | Agent + centralized manager |
| **Can block first request?** | No | Yes | Tetragon can (enforcement mode) | No (detect-and-respond) |
| **Cross-app correlation** | Yes (unified entity graph) | Limited | No (node-local) | Log correlation rules |
| **Kernel/runtime visibility** | Ingests Tetragon, Falco, Hubble | No | Native | Agent-based file/process monitoring |
| **Containment model** | Signed, TTL-bounded, reversible | Block/allow rules | Tetragon: kill process | Active response scripts |
| **Application latency impact** | None (async emitter) | Adds to request path | None (kernel-level) | None (log-based) |
| **Policy model** | Capability-based, DENY > ALLOW | Rule-based | Enforcement policies | Rule-based |

**This project does not replace** Falco or Tetragon — it ingests their telemetry and adds cross-application correlation, identity resolution, and graduated containment that those tools don't provide individually. It also does not replace an inline WAF for known-signature blocking.

---

## Project Status

The repository is under active development. **Architecture v4 supplements v3 and takes precedence where they conflict.** The current V3-era Phase 6–8 code is a prototype baseline, not a completed implementation of V4's sensor hardening or prevention guarantees.

- **V3 foundations present:** Core control-plane features, native sensor prototype, Port Guardian, opt-in userspace Native Enforcer, and Corvus standalone mode with SQLite persistence. Their V4 replacements and safety requirements are not complete.
- **V4 hardening is the current gate:** Phase 6A must first be audited on a real Linux kernel; then LSM capture, explicit degraded health reporting, host/service onboarding, ingress SYN sensing, separated decisions, and safe bouncers must be implemented and tested in dependency order.
- **Phase 10 partial:** Portable HTTP/DNS/TLS parsing and an ingestion API exist. AF_XDP capture, live capture/reassembly, and process-flow attribution remain outstanding.
- **Frozen for Hardening:** Advisory LLM Reasoning (old Phase 6) remains frozen pending V4 hardening and Phase 10 acceptance. It must not gain an enforcement/write path.

---

## Technology Stack

| Layer | Technology | Role |
| :--- | :--- | :--- |
| **Native Kernel Sensor** | Rust + `aya` (`sensor-native`) | V3 syscall tracepoint/kprobe prototype; user-pointer observations are TOCTOU-prone and not authoritative. V4 LSM capture and degraded health reporting remain gated on kernel validation. |
| **External Sensor Adapters** | eBPF (Cilium Tetragon, Falco, Hubble) | Ingests process execution, syscall alerts, and L3-L7 network flows from Kubernetes daemonsets via REST. |
| **Core Security Engine** | Rust (`tokio`, Axum) | Event ingestion, sliding-window detection, in-memory correlation graph, Ed25519 signed containment. |
| **API & Streaming** | Rust (Axum REST & WebSockets) | Telemetry ingestion endpoints and real-time event streaming to the dashboard. |
| **Operational & Durable State**| In-memory hot state; SQLite durable sink (Standalone) | Standalone (`corvus`) persists events, incidents, and containment audit records. Distributed mode can use Redis hot state; PostgreSQL persistence is not implemented. |
| **OS-Level Enforcement** | `nftables`, SIGKILL (`enforcer`) | V3 opt-in post-detection actions only; not synchronous prevention. V4 audit-first LSM deny and safe bouncer redesign remain unimplemented. |
| **Operations Dashboard** | React + TypeScript + Vite | Dark-mode dashboard with live WebSocket feed, sensor filtering, mode switcher, and incident triage. |
| **Advisory AI (Phase 11)** | Python worker (`services/llm-worker`) | Off-path advisory assistant for ambiguous incidents (Mode B). Strictly advisory, zero execution privileges. |

---

### Architecture v4 implementation status

V4 supersedes V3's Phase 6 capture path, Phase 7 scan-detection design, and Phase 8 enforcement design:

- **Phase 6:** The current sensor reads syscall arguments from user memory in eBPF and uses `sys_connect`/`sys_bind`/`sys_accept4` kprobes. This is vulnerable to TOCTOU mismatches, can attach incorrectly across kernel architectures, does not capture the accepted peer, and does not report stable `(pid, start_time)` identity. It is not LSM capture and must be treated as degraded until V4 Phases 6A–6D are accepted.
- **Phase 7:** The current Port Guardian detects patterns from local bind/connect/accept telemetry for registered ports. It does not observe ingress SYNs to closed ports, discover/reconcile existing listeners, or require service approval. V4 Phases 7A–7C replace these assumptions.
- **Phase 8:** The current enforcer performs post-detection userspace actions. It does not synchronously deny exec/connect in LSM hooks, and its current nftables rollback/process-kill model does not satisfy V4's isolated, idempotent bouncer, expiry, lockout-prevention, and PID-reuse requirements.
- **V4 validation is not complete:** No real-kernel Phase 6A audit, LSM lab run, or V4 acceptance test has been recorded. Do not treat a successful Windows workspace build/test as evidence for kernel behavior.

See [DSCP_Phase_Architecture_v4.md](DSCP_Phase_Architecture_v4.md) for the authoritative phase gates and known residual limits. Do not begin V4 Phase 6B until the Phase 6A audit is completed on a Linux 5.15+ lab kernel.

## 12-Phase Development Roadmap

The platform is engineered systematically across twelve explicit phases:

- [x] **Phase 1: Architecture Core, Ingestion Pipeline & Minimal Observable Slice**
  - Canonical event model with sensor fidelity (`SecurityEvent`).
  - Decoupled Event Stream abstraction & selective durable writer.
  - Non-blocking application middleware.
  - Live streaming React + TypeScript dashboard with WebSocket connectivity.
- [x] **Phase 2: Hot State Operational Engine & Deterministic Detection**
  - Sliding-window rate tracking with in-memory ring-buffer.
  - High-confidence deterministic rules (credential brute-force, rapid API enumeration, unauthorized bursts, container shell spawn).
  - Signal accumulation, dynamic risk scoring, automated incident synthesis and lifecycle management.
  - RESTful incident management and real-time WebSocket incident streaming.
- [x] **Phase 3: Identity Resolution, Cross-App Correlation & Capability Context**
  - Canonical entity resolution across heterogeneous identifiers (IP, session token, user ID, container ID, PID).
  - In-memory context graph tracking relationships across applications with automated TTL eviction.
  - Multi-stage cross-application attack sequence detector (Reconnaissance → Lateral Movement → Exfiltration).
  - Capability context inference inspired by Deno's permission model.
- [x] **Phase 4: Capability Policy Engine & Graduated Containment**
  - Fine-grained scoped capability permissions with absolute `DENY` precedence over `ALLOW`.
  - Versioned declarative policy bundles with Mode C dry-run simulation.
  - Ed25519 cryptographically signed containment commands with mandatory TTLs and replay protection.
  - Graduated surgical actions (revoke session, throttle actor, block network, revoke capability, restrict scope, isolate service) with explicit rollback.
  - Local in-process `ContainmentGuard` for sub-millisecond cached enforcement.
- [x] **Phase 5: External Sensor Adapters (Cilium Tetragon, Falco, Hubble)**
  - REST ingestion endpoints: `/api/v1/sensors/tetragon`, `/api/v1/sensors/falco`, `/api/v1/sensors/hubble`.
  - Normalization of raw eBPF/syscall/flow telemetry into canonical `SecurityEvent` with full raw payload preservation (Sensor Fidelity Invariant).
  - High-confidence kernel detection (container shell spawn, syscall anomalies, dropped network egress).
- [ ] **Phase 6: Native eBPF Sensor — V3 prototype present; V4 hardening required**
  - In-tree eBPF programs for Linux 5.15+ LTS kernel: `sys_enter_execve` tracepoint and `sys_connect`, `sys_bind`, `sys_accept4` kprobes.
  - 256 KB non-blocking kernel ring buffer (`EVENTS`).
  - These syscall-argument probes are TOCTOU-prone and do not establish a trustworthy, complete view of kernel activity. Replace/label them per V4 Phases 6A–6D before relying on them.
- [ ] **Phase 7: Port Guardian — V3 prototype present; V4 discovery and ingress sensing required**
  - Real-time server port ownership registry updated by `kernel.net.bind` events.
  - Existing connection-based detections do not see ingress SYN scans of closed ports. V4 replaces scan detection with TC ingress aggregation and adds an approved service lifecycle.
- [ ] **Phase 8: Enforcement — V3 post-hoc prototype present; V4 decision/bouncer redesign required**
  - Current userspace enforcement is post-detection, not synchronous prevention. V4 requires audit-first LSM deny decisions and safe, separately managed bouncers.
- [x] **Phase 9: Standalone Mode (`corvus`)**
  - Standalone binary mode with SQLite durable records and in-memory hot state.
  - External Redis and PostgreSQL services are not required in standalone mode; dashboard assets are not embedded.
- [ ] **Phase 10: AF_XDP + L7 Payload Inspection (partial)**
  - Implemented portable HTTP/DNS/TLS parsing, a bounded TCP reassembly component, and an ingestion API.
  - AF_XDP zero-copy redirection and live capture/reassembly integration remain outstanding.
- [ ] **Phase 11: Advisory LLM Reasoning (Mode B)**
  - Off-path advisory assistant for ambiguous multi-stage incidents.
  - Deterministic Policy Validation Gate enforcing `DENY > ALLOW` precedence before containment dispatch.
  - Fault-tolerant fallback: control plane gracefully falls back to Mode A if advisory worker is unreachable.
- [ ] **Phase 12: Full Stack Observability, Benchmarking & Packaging**
  - Docker Compose deployment with Redis, PostgreSQL, Prometheus, and Grafana.
  - Sustained load testing, detection-to-containment latency benchmarking, and Debian/RPM packages.

---

## Known Limitations

This project has several unsolved hard problems documented in [THREAT_MODEL.md](THREAT_MODEL.md):

- **Telemetry integrity**: A compromised application can forge or suppress its own telemetry. The system currently trusts emitters.
- **Agent attack surface**: The local agent and its Ed25519 signing keys are themselves targets. Key distribution, rotation, and revocation are not yet implemented.
- **Identity resolution errors**: A false entity merge means an innocent user could be contained. There is no undo mechanism for identity graph corrections.
- **In-memory state**: The context graph and correlation state live in memory. A restart loses all state, and the architecture doesn't yet support horizontal scaling.
- **Distributed persistence**: The distributed feature can use Redis for hot state, but durable PostgreSQL storage is not implemented; the current distributed sink is in-memory.
- **Native enforcement**: Disabled unless `NATIVE_ENFORCER=true`; supported actions require Linux privileges, and process termination is irreversible.
- **Packet capture**: Phase 10 currently inspects submitted payloads; it does not capture packets from a live interface.
- **Kernel coverage**: The V3 sensor does not observe io_uring-only activity and does not detect a root attacker detaching or blinding eBPF programs. V4 plans health/tamper signals; these report limitations but do not eliminate them.
- **Enrollment and service approval**: V3 does not authenticate/enroll hosts or require operator approval before a discovered service becomes protected.

These are acknowledged limitations, not solved problems. Documenting them here is intentional.

---

## Quickstart & Local Setup

### 1. Prerequisites
- **Rust**: 1.80+ (`stable` toolchain)
- **Node.js**: 20+ and npm
- **Python**: 3.11+ (for integration tests and benchmarks)

> **Note:** The default process uses in-memory state. Standalone mode (`corvus`) additionally persists events, incidents, and containment records to SQLite. Distributed durable PostgreSQL storage is not yet implemented.

### 2. Run the Security Control Plane Server
```powershell
cargo run -p security-control-plane
```
The API server listens on `http://localhost:8080` with the WebSocket stream at `ws://localhost:8080/api/v1/ws/events`.

To run standalone mode using the sample [corvus.toml](corvus.toml) configuration:
```powershell
cargo run -p security-control-plane --bin corvus -- --config corvus.toml
```
Set `NATIVE_ENFORCER=true` only when explicitly enabling supported Linux OS enforcement actions and after reviewing the security guidance in [SECURITY.md](SECURITY.md).

### 3. Launch the Operations Dashboard
```powershell
cd frontend
npm install
npm run dev
```
Open `http://localhost:5173` to view the live dashboard.
### 4. Phase 6 Native eBPF Sensor (Optional / Linux Bare Metal)
Standard builds run everywhere without root or eBPF toolchains. To compile and run the native eBPF kernel probes on a Linux host (kernel 5.15+ LTS with BTF):
```bash
# 1. Install toolchain prerequisites (one-time)
rustup target add bpfel-unknown-none
cargo install bpf-linker

# 2. Build isolated eBPF kernel program
cd crates/sensor-native-ebpf
cargo build --release
cd ../..

# 3. Run control plane with native sensor enabled (requires root or CAP_BPF)
sudo NATIVE_SENSOR=true RUST_LOG=info cargo run -p security-control-plane
```

### 5. Run the Integration Tests
```powershell
# Rust unit tests (all workspace crates, non-root)
cargo test --workspace

# Integration test suites (server must be running at http://localhost:8080)
python tests/test_phase1_slice.py
python tests/test_phase2_engine.py
python tests/test_phase3_correlation.py
python tests/test_phase4_containment.py
python tests/test_phase5_sensors.py
python tests/test_phase6_native_sensor.py
python tests/test_phase7_port_guardian.py
python tests/test_phase10_packet_inspector.py

# Standalone SQLite smoke test; build Corvus first
cargo build -p security-control-plane --bin corvus
python tests/test_phase9_standalone.py
```

The native eBPF integration test and OS enforcer require a suitable Linux host; portable parser and API tests do not provide live AF_XDP capture validation.

### 6. Run the Benchmark
```powershell
python benchmarks/measure_overhead.py
```

---

## Documentation

- [Architecture Overview](docs/ARCHITECTURE.md)
- [Threat Model & Known Limitations](THREAT_MODEL.md)
- [Use Cases](docs/USE-CASES.md)
- [Detection & Correlation](docs/DETECTION-AND-CORRELATION.md)
- [Changelog](CHANGELOG.md)

---

## License

This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**. See the [LICENSE](LICENSE) file for full terms.

The AGPL ensures that all modifications — including those deployed as a network service — remain open source and available to the community. See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines and [SECURITY.md](SECURITY.md) for our vulnerability disclosure policy.
