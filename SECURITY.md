# Security Policy

### 1. Supported Versions

Security updates and vulnerability patches are applied to the active development branch and the latest tagged releases.

| Version | Supported          | Status                                                  |
| ------- | ------------------ | ------------------------------------------------------- |
| 0.6.x   | :white_check_mark: | Active Development (V3 prototype; V4 hardening pending) |
| 0.5.x   | :white_check_mark: | Maintained (Phase 5 — External Sensor Adapters)         |
| 0.4.x   | :white_check_mark: | Maintained (Phase 4 — Capability Policy & Containment)  |
| 0.3.x   | :white_check_mark: | Maintained (Phase 3 — Identity Resolution & Correlation)|
| 0.2.x   | :white_check_mark: | Maintained (Phase 2 — Detection Engine & Hot State)     |
| 0.1.x   | :white_check_mark: | Maintained (Phase 1 — Core Architecture)                |
| < 0.1   | :x:                | Unsupported                                             |

---

## 2. Reporting a Vulnerability

The maintainers of the **Distributed Security Control Plane** take the security of this platform seriously. Because this software coordinates threat containment and policy enforcement across multiple enterprise applications, vulnerabilities within the control plane are treated with the highest severity.

### How to Report

If you discover a security vulnerability, architectural weakness, or potential bypass:

1. **Do NOT disclose the issue publicly** via GitHub issues, discussions, pull requests, or social media.
2. **Use GitHub's private vulnerability reporting**:
   - Navigate to the repository's **Security** tab → **Advisories** → **Report a vulnerability**.
   - This creates a private, confidential thread visible only to maintainers.
3. **Alternatively**, send a detailed report via email to the project maintainers.

### What to Include in Your Report

| Field                    | Details                                                                        |
| :----------------------- | :----------------------------------------------------------------------------- |
| **Component Affected**   | Specify the crate or module (e.g., `crates/sensor-native`, `crates/engine`, `crates/correlator`, `crates/control-plane`, `crates/agent-sdk`, `crates/common`). |
| **Severity Estimate**    | Your assessment: Critical / High / Medium / Low.                               |
| **Reproduction Steps**   | Step-by-step instructions or a proof-of-concept payload.                       |
| **Impact Assessment**    | Potential impact on application availability, containment integrity, data confidentiality, or trust boundaries. |
| **Affected Versions**    | Which version(s) are affected, if known.                                       |
| **Suggested Fix**        | Optional: your recommended remediation approach.                               |

---

## 3. Threat Model & Root of Trust Boundaries

The intended architecture uses explicit trust boundaries, but the current V3-era sensor and enforcer do not meet V4's capture-integrity or synchronous-deny requirements. These boundaries are not substitutes for API authentication, host isolation, or deployment hardening:

```text
       UNTRUSTED INPUTS                  ROOT OF TRUST                CONSUMERS
  ┌─────────────────────────┐     ┌─────────────────────────┐     ┌──────────────┐
  │  Application Telemetry  │ ──► │                         │ ──► │  Dashboard   │
  ├─────────────────────────┤     │   Deterministic Rust    │     └──────────────┘
  │  Native eBPF Sensor     │ ──► │      Policy Engine      │     ┌──────────────┐
  │ (execve, connect, bind) │     │                         │ ──► │ Local Agents │
  ├─────────────────────────┤     │  (Validates, Authorizes,│     │ (Containment)│
  │ External Sensors        │ ──► │   Signs All Commands)   │     └──────────────┘
  │ (Tetragon/Falco/Hubble) │     │                         │     ┌──────────────┐
  └─────────────────────────┘     └────────────┬────────────┘ ──► │ OS Enforcers │
                                               │                  │(nftables/process)│
                                  Strict Schema & Policy Gate     └──────────────┘
                                               │
                                  ┌────────────▼────────────┐
                                  │   Off-Path LLM Worker   │
                                  │   (Advisory Only, Mode B)│
                                  └─────────────────────────┘
```

### Core Security Invariants (Architecture v4 supplements v3)

1. **Zero Request-Path Coupling**: Normal application requests (`Client -> App -> Response`) must never synchronously wait for security ingestion, correlation, detection, or policy evaluation.
2. **Deterministic Core as Root of Trust**: The deterministic Rust policy engine is intended to make binding decisions. The existing V3 userspace enforcer is post-detection and is not synchronous prevention.
3. **Cryptographically Signed Containment**: All containment commands are Ed25519-signed with mandatory TTLs, sequence IDs, and replay protection.
4. **Universal Normalization**: Every sensor (native eBPF, external adapters, application emitters) normalizes to canonical `SecurityEvent`.
5. **Absolute DENY Precedence**: In the capability policy engine, `DENY` strictly takes precedence over `ALLOW`.
6. **Explicit Storage Guarantees**: Standalone mode persists events, incidents, and containment records in SQLite. Distributed mode can use Redis for hot state; PostgreSQL durable storage is not implemented, and in-memory fallback is not durable.
7. **No Panic in Production**: Zero `unwrap()` in production execution paths; errors must be handled gracefully with `?`, `match`, or structured error types.
8. **Structured Observability**: Tracing only (`tracing::info!`, `warn!`, `error!`); no raw `println!` in production code.
9. **Separated eBPF Compilation**: Standard `cargo build` produces a working binary on any platform without requiring an eBPF toolchain.
10. **Non-Privileged Testability**: Portable parsers and most unit tests run without root privileges. Linux kernel capture and system enforcement require platform-specific integration validation.

### Current Phase 6–8 limitations and V4 gates

- **Capture is not TOCTOU-safe:** The degraded eBPF fallback reads exec filenames and connect/bind sockaddr data through user pointers at syscall tracepoints. These observations can differ from the data the kernel consumes. Architecture-dependent kprobes have been removed, but accepted-peer attribution is absent and process identity still uses PID-only plus userspace `/proc` reads. io_uring-only activity is not observed. Tracepoint events must not be treated as authoritative.
- **No synchronous deny:** Native enforcement is opt-in with `NATIVE_ENFORCER=true`, but its actions run after detection. They do not prevent the syscall that generated the event.
- **Unsafe process/firewall behavior remains:** The current backend uses PID-based `kill -9` and a shared nftables structure. PID reuse can target another process, broad rollback can disturb unrelated firewall state, and process termination is irreversible. Keep the enforcer disabled in production until V4's ProcessKey/pidfd and isolated, expiring bouncer design is implemented and validated.
- V4 requires audit-first enforcement, explicit expiry, `never_block` protection, no automatic promotion, and fail-open detach behavior. The V3 enforcer does not currently satisfy that complete safety model.
- The API/control plane must be isolated and authenticated at the deployment boundary. Do not expose telemetry or containment endpoints to untrusted networks; the application does not itself provide TLS or caller authentication.

LSM-BPF capture and in-kernel deny require a kernel built with `CONFIG_BPF_LSM` and `bpf` present in the active LSM list. Enabling it requires appending `bpf` to the existing kernel command-line LSM list and rebooting; do not replace the existing list.

### Phase 10 Packet Inspection Boundaries

HTTP/DNS/TLS parsing is currently exposed through a payload-ingestion API. The code does not attach an AF_XDP socket, redirect live packets, or connect TCP reassembly to a live capture path. Treat the feature as an inspection component, not as an inline firewall or complete network sensor.

4. **Out-of-Band Application Resilience**: Normal application traffic (`Client -> App -> Response`) never synchronously blocks on the control plane. In the event of a security controller outage, protected applications continue serving normal requests uninterrupted.

5. **Identity Isolation**: The Identity Resolution and Correlation Engine operates on derived canonical identifiers. Raw PII is never stored in the correlation graph — only hashed or tokenized entity references are maintained.

6. **Capability Least-Privilege**: Inferred capabilities follow a Deno-style model — each entity's effective permissions are dynamically computed from observed behavior, never statically granted.

---

## 4. Security-Relevant Architecture Decisions

### Why AGPL-3.0?

This project is licensed under the **GNU Affero General Public License v3.0** specifically because:

- The control plane is designed to operate as a **network service**. The AGPL's Section 13 ensures that organizations running modified versions as a service must make corresponding source code available — preventing proprietary forks from fragmenting the security community's collective defense.
- Strong copyleft ensures all improvements to detection rules, correlation logic, and containment strategies remain available to the community.

### Supply Chain Security

- **Minimal Dependencies**: The core engine crates (`engine`, `correlator`, `common`) minimize external dependencies to reduce supply chain attack surface.
- **Cargo Audit**: Run `cargo audit` regularly to check for known vulnerabilities in dependencies.
- **Lockfile Committed**: `Cargo.lock` is committed to the repository for reproducible builds.

### Deployment Hardening Recommendations

When deploying this control plane in production:

1. **Network Isolation**: The control plane API should be accessible only from trusted application agents and the operations dashboard, not the public internet.
2. **TLS Everywhere**: All telemetry ingestion and command channels should use TLS 1.3.
3. **Principle of Least Privilege**: The control plane process should run with minimal OS privileges; it does not require root access.
4. **Audit Logging**: Use standalone SQLite persistence for events, incidents, and containment records where appropriate, and protect the database file with OS permissions and backups. PostgreSQL-backed durable logging is not currently available.
5. **Key Management**: Ed25519 signing keys for containment commands should be stored in a hardware security module (HSM) or secure key vault in production deployments.
6. **Native Enforcement**: Keep `NATIVE_ENFORCER` disabled unless needed. Review each action's privileges and impact; process termination cannot be rolled back.

---

## 5. Acknowledgments

We gratefully acknowledge security researchers who responsibly disclose vulnerabilities. Unless anonymity is requested, reporters will be credited in the security advisory and the project's release notes.

---

**Thank you for helping keep the Distributed Security Control Plane secure.** 🛡️
