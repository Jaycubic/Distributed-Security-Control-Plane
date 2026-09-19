# Security Policy

## 1. Supported Versions

Security updates and vulnerability patches are applied to the active development branch and the latest tagged releases.

| Version | Supported          | Status                                      |
| ------- | ------------------ | ------------------------------------------- |
| 0.3.x   | :white_check_mark: | Active Development (Phase 3 — Correlation)  |
| 0.2.x   | :white_check_mark: | Maintained (Phase 2 — Detection Engine)     |
| 0.1.x   | :white_check_mark: | Maintained (Phase 1 — Core Architecture)    |
| < 0.1   | :x:                | Unsupported                                 |

---

## 2. Reporting a Vulnerability

The maintainers of the **Distributed Security Control Plane** take the security of this platform seriously. Because this software coordinates threat containment and policy enforcement across multiple enterprise applications, vulnerabilities within the control plane are treated with the highest severity.

### How to Report

If you discover a security vulnerability, architectural weakness, or potential bypass:

1. **Do NOT disclose the issue publicly** via GitHub issues, discussions, pull requests, or social media.
2. **Use GitHub's private vulnerability reporting**:
   - Navigate to the repository's **Security** tab → **Advisories** → **Report a vulnerability**.
   - This creates a private, confidential thread visible only to maintainers.
3. **Alternatively**, send a detailed report via email to the project maintainers (see the repository's GitHub profile for contact information).

### What to Include in Your Report

| Field                    | Details                                                                        |
| :----------------------- | :----------------------------------------------------------------------------- |
| **Component Affected**   | Specify the crate or module (e.g., `crates/engine`, `crates/correlator`, `crates/control-plane`, `crates/agent-sdk`, `crates/common`, or `frontend`). |
| **Severity Estimate**    | Your assessment: Critical / High / Medium / Low.                               |
| **Reproduction Steps**   | Step-by-step instructions or a proof-of-concept payload.                       |
| **Impact Assessment**    | Potential impact on application availability, containment integrity, data confidentiality, or trust boundaries. |
| **Affected Versions**    | Which version(s) are affected, if known.                                       |
| **Suggested Fix**        | Optional: your recommended remediation approach.                               |

### Disclosure Timeline

| Stage                    | Target Timeframe                                         |
| :----------------------- | :------------------------------------------------------- |
| **Acknowledgment**       | Within **48 hours** of receiving the report.             |
| **Triage & Reproduction**| Within **5 business days**.                              |
| **Fix Development**      | Severity-dependent (Critical: 7 days, High: 14 days).   |
| **Coordinated Disclosure** | Fix released before or simultaneously with public advisory. Reporter is credited unless anonymity is requested. |

### Safe Harbor

We consider security research conducted in good faith to be authorized. We will not pursue legal action against researchers who:

- Make a good-faith effort to avoid privacy violations, data destruction, and service disruption.
- Only interact with accounts they own or have explicit permission to test.
- Report vulnerabilities through the channels described above.
- Allow reasonable time for remediation before any public disclosure.

---

## 3. Threat Model & Root of Trust Boundaries

The system is designed with explicit trust boundaries to ensure that a compromise of any single sensor, application, or model cannot compromise the entire control plane:

```text
       UNTRUSTED INPUTS                  ROOT OF TRUST                CONSUMERS
  ┌─────────────────────────┐     ┌─────────────────────────┐     ┌──────────────┐
  │  Application Telemetry  │ ──► │                         │ ──► │  Dashboard   │
  ├─────────────────────────┤     │   Deterministic Rust    │     └──────────────┘
  │  Tetragon Kernel Feed   │ ──► │      Policy Engine      │     ┌──────────────┐
  ├─────────────────────────┤     │                         │ ──► │ Local Agents │
  │  Falco Syscall Alerts   │ ──► │  (Validates, Authorizes,│     │ (Containment)│
  ├─────────────────────────┤     │   Signs All Commands)   │     └──────────────┘
  │  Hubble Flow Telemetry  │ ──► │                         │
  └─────────────────────────┘     └────────────┬────────────┘
                                               │
                                 Strict Schema & Policy Gate
                                               │
                                  ┌────────────▼────────────┐
                                  │   Off-Path LLM Worker   │
                                  │   (Advisory Only, Mode B)│
                                  └─────────────────────────┘
```

### Core Security Invariants

1. **Telemetry is Untrusted Input**: All incoming events from application agents, Tetragon, Falco, and Hubble are strictly validated for payload size, timestamp skew, and format before entering the event stream.

2. **Deterministic Engine is Root of Trust**: The Rust policy engine alone makes binding containment decisions. The LLM worker and the frontend dashboard sit **outside** the root of trust and have zero administrative execution authority.

3. **Signed Containment Commands**: All agent response actions (`REVOKE_SESSION`, `THROTTLE_ACTOR`, `BLOCK_NETWORK`, `ISOLATE_SERVICE`) are cryptographically signed with Ed25519, carrying a mandatory expiration timestamp (TTL) and rollback recipe.

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
