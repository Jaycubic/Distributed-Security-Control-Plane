# Security Policy

### 1. Supported Versions

Security updates and vulnerability patches are applied to the active development branch and the latest tagged releases.

| Version | Supported          | Status                                                  |
| ------- | ------------------ | ------------------------------------------------------- |
| 0.6.x   | :white_check_mark: | Active Development (Phase 6 — Native eBPF Sensor)       |
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

The system is designed with explicit trust boundaries to ensure that a compromise of any single sensor, application, or model cannot compromise the control plane:

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
                                               │                  │(nftables/XDP)│
                                  Strict Schema & Policy Gate     └──────────────┘
                                               │
                                  ┌────────────▼────────────┐
                                  │   Off-Path LLM Worker   │
                                  │   (Advisory Only, Mode B)│
                                  └─────────────────────────┘
```

### Core Security Invariants (Master Architecture v3)

1. **Zero Request-Path Coupling**: Normal application requests (`Client -> App -> Response`) must never synchronously wait for security ingestion, correlation, detection, or policy evaluation.
2. **Deterministic Core as Root of Trust**: The deterministic Rust capability policy engine alone makes binding containment decisions. LLM/AI workers have zero direct execution authority.
3. **Cryptographically Signed Containment**: All containment commands are Ed25519-signed with mandatory TTLs, sequence IDs, and replay protection.
4. **Universal Normalization**: Every sensor (native eBPF, external adapters, application emitters) normalizes to canonical `SecurityEvent`.
5. **Absolute DENY Precedence**: In the capability policy engine, `DENY` strictly takes precedence over `ALLOW`.
6. **Graceful Fallback Resilience**: The control plane must survive Redis/PostgreSQL outages; `MemoryHotState` and in-memory streams serve as resilient fallbacks.
7. **No Panic in Production**: Zero `unwrap()` in production execution paths; errors must be handled gracefully with `?`, `match`, or structured error types.
8. **Structured Observability**: Tracing only (`tracing::info!`, `warn!`, `error!`); no raw `println!` in production code.
9. **Separated eBPF Compilation**: Standard `cargo build` produces a working binary on any platform without requiring an eBPF toolchain.
10. **Non-Privileged Testability**: Every phase includes unit tests and integration tests that run without root privileges.timestamp (TTL) and rollback recipe.

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
4. **Audit Logging**: Enable durable PostgreSQL audit logging for all containment actions and incident lifecycle transitions.
5. **Key Management**: Ed25519 signing keys for containment commands should be stored in a hardware security module (HSM) or secure key vault in production deployments.

---

## 5. Acknowledgments

We gratefully acknowledge security researchers who responsibly disclose vulnerabilities. Unless anonymity is requested, reporters will be credited in the security advisory and the project's release notes.

---

**Thank you for helping keep the Distributed Security Control Plane secure.** 🛡️
