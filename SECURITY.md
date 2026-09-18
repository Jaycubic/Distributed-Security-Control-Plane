# Security Policy

## 1. Supported Versions

Security updates and vulnerability patches are applied to the active development branch and the latest minor release tags.

| Version | Supported          | Status |
| ------- | ------------------ | ------ |
| 0.1.x   | :white_check_mark: | Active Development (Phase 1) |

---

## 2. Reporting a Vulnerability

The maintainers of the **Distributed Security Control Plane** take the security of this platform seriously. Because this software coordinates threat containment and policy enforcement across multiple enterprise applications, vulnerabilities within the control plane are treated with the highest severity.

If you discover a security vulnerability or potential architectural weakness:

1. **Do not disclose the issue publicly** via GitHub issues, discussions, or social media.
2. Send a detailed report via encrypted email to:  
   `security@controlplane.internal` (or submit a confidential [GitHub Security Advisory](https://github.com/)).
3. Include the following details:
   - Component affected (`crates/common`, `crates/control-plane`, `crates/agent-sdk`, or `frontend`).
   - Step-by-step reproduction steps or proof-of-concept payload.
   - Potential impact on application availability or containment integrity.

### Disclosure Timeline
- **Initial Response**: Within 48 hours acknowledging receipt.
- **Triage & Reproduction**: Within 5 business days.
- **Fix & Advisory Release**: Coordinated with the reporter before public disclosure.

---

## 3. Threat Model & Root of Trust Boundaries

The system is designed with explicit boundaries to ensure that a compromise of any single sensor, application, or model cannot compromise the entire control plane:

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

### Core Security Invariants:
1. **Telemetry is Untrusted Input**: All incoming events from application agents, Tetragon, Falco, and Hubble are strictly validated for payload size, timestamp skew, and format before entering the event stream.
2. **Deterministic Engine is Root of Trust**: The Rust policy engine alone makes binding containment decisions. The LLM worker and the frontend dashboard sit **outside** the root of trust and have zero administrative execution authority.
3. **Signed Containment Commands**: All agent response actions (`REVOKE_SESSION`, `THROTTLE_ACTOR`, `BLOCK_NETWORK`, `ISOLATE_SERVICE`) are cryptographically signed with Ed25519, carrying a mandatory expiration timestamp (TTL) and rollback recipe.
4. **Out-of-Band Application Resilience**: Normal application traffic (`Client -> App -> Response`) never synchronously blocks on the control plane. In the event of a security controller outage, protected applications continue serving normal requests uninterrupted.
