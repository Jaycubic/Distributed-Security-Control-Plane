# Distributed Security Control Plane

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Rust: 1.80+](https://img.shields.io/badge/Rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)
[![React: 18.3](https://img.shields.io/badge/Frontend-React_%2B_TypeScript-61dafb.svg)](https://react.dev/)
[![Architecture: Out--of--Band](https://img.shields.io/badge/Architecture-Out--of--Band_Control_Plane-emerald.svg)](#core-architectural-invariant)

> **An open-source, out-of-band security control plane that asynchronously collects security telemetry from applications and runtime sensors, resolves identity, correlates activity across services, detects abnormal behavior, and coordinates graduated containment — without placing security analysis on the synchronous application request path.**

**Core idea:** security should observe and act on applications without becoming a dependency of their normal request path.

[Architecture](#system-architecture) · [Trade-offs](#design-trade-offs) · [Quickstart](#quickstart--local-setup) · [Roadmap](#7-phase-development-roadmap) · [Threat Model](THREAT_MODEL.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

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

The repository is under active development, organized as a phased security-engineering project following the **Master Architecture v3** roadmap.

- **Complete & Production Ready:** Phases 1–5 (core architecture, ingestion pipeline, deterministic rule engine, hot state, identity resolution, cross-app context graph, capability policy engine with `DENY > ALLOW`, Ed25519 signed containment, and external sensor adapters for Tetragon/Falco/Hubble).
- **Phase 6 Implemented:** Native eBPF Sensor (`crates/sensor-native`, `crates/sensor-native-ebpf`, `crates/sensor-native-common`) built on Rust `aya`, providing in-tree kernel visibility without third-party daemon dependencies.
- **Next Up:** Phase 7 (Port Guardian), Phase 8 (Native Enforcer: `nftables`/XDP), Phase 9 (Corvus Standalone with SQLite), Phase 10 (AF_XDP L7 Packet Inspection).
- **Frozen for Hardening:** Advisory LLM Reasoning (old Phase 6) is frozen until Phase 10 is complete to ensure the kernel, port, and enforcement foundation is solid (Invariant #2: Deterministic core is root of trust).

---

## Technology Stack

| Layer | Technology | Role |
| :--- | :--- | :--- |
| **Native Kernel Sensor** | Rust + `aya` (`sensor-native`) | In-tree eBPF sensor capturing `execve`, `connect`, `bind`, and `accept4` directly from the Linux kernel. |
| **External Sensor Adapters** | eBPF (Cilium Tetragon, Falco, Hubble) | Ingests process execution, syscall alerts, and L3-L7 network flows from Kubernetes daemonsets via REST. |
| **Core Security Engine** | Rust (`tokio`, Axum) | Event ingestion, sliding-window detection, in-memory correlation graph, Ed25519 signed containment. |
| **API & Streaming** | Rust (Axum REST & WebSockets) | Telemetry ingestion endpoints and real-time event streaming to the dashboard. |
| **Operational & Durable State**| In-Memory & SQLite (Standalone) / Redis & PostgreSQL (Distributed) | Dual-mode state architecture. Single-binary standalone (`corvus`) or horizontally scalable distributed setup. |
| **OS-Level Enforcement** | `nftables`, XDP, SIGKILL (`enforcer`) | Out-of-band kernel/network containment executing signed Ed25519 containment commands. |
| **Operations Dashboard** | React + TypeScript + Vite | Dark-mode dashboard with live WebSocket feed, sensor filtering, mode switcher, and incident triage. |
| **Advisory AI (Phase 11)** | Python worker (`services/llm-worker`) | Off-path advisory assistant for ambiguous incidents (Mode B). Strictly advisory, zero execution privileges. |

---

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
- [x] **Phase 6: Native eBPF Sensor (`aya`)**
  - In-tree eBPF programs for Linux 5.15+ LTS kernel: `sys_enter_execve` tracepoint and `sys_connect`, `sys_bind`, `sys_accept4` kprobes.
  - 256 KB non-blocking kernel ring buffer (`EVENTS`).
  - Userspace loader and normalizer converting kernel events directly to `SecurityEvent` with `SensorType::NativeSensor`.
  - Zero third-party daemon dependency for bare-metal Linux server deployments.
- [ ] **Phase 7: Port Guardian**
  - Real-time server port ownership registry updated by `kernel.net.bind` events.
  - Sliding-window port-scan and connection-flood detection in `HotStateStore`.
  - Port binding query API for operational dashboard inspection.
- [ ] **Phase 8: Native Enforcer**
  - OS-level containment via `nftables` DROP rules and process SIGKILL.
  - Direct execution of signed Ed25519 `SignedContainmentCommand` payloads without requiring application code changes.
- [ ] **Phase 9: Standalone Mode (`corvus`)**
  - Single binary package with SQLite durable sink and in-memory hot state.
  - Embedded static assets for operations dashboard.
  - Zero external dependencies (no Redis, no PostgreSQL).
- [ ] **Phase 10: AF_XDP + L7 Payload Inspection**
  - AF_XDP zero-copy packet redirection.
  - TCP stream reassembly and protocol anomaly detection (HTTP/1.1, DNS tunneling, TLS SNI inspection).
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

These are acknowledged limitations, not solved problems. Documenting them here is intentional.

---

## Quickstart & Local Setup

### 1. Prerequisites
- **Rust**: 1.80+ (`stable` toolchain)
- **Node.js**: 20+ and npm
- **Python**: 3.11+ (for integration tests and benchmarks)

> **Note:** The standalone mode runs fully in-memory — no Redis or PostgreSQL needed. External state stores are planned for Phase 7 and will ship with a Docker Compose configuration.

### 2. Run the Security Control Plane Server
```powershell
cargo run -p security-control-plane
```
The API server listens on `http://localhost:8080` with the WebSocket stream at `ws://localhost:8080/api/v1/ws/events`.

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
```

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
