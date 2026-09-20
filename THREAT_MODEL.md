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

### Mitigations (Planned)
- **Kernel-level sensors** (Tetragon, Falco, Hubble) are harder to tamper with because they run in kernel space or as privileged DaemonSets, outside the application's control. Cross-referencing application telemetry against kernel telemetry can detect suppression — if Tetragon sees a process execution that the application emitter didn't report, that's a signal.
- **Mutual TLS or signed telemetry** on the emitter → control plane channel would prevent unauthorized sources from injecting events, though it doesn't prevent a compromised app from dropping its own events.
- **Anomaly detection on telemetry volume**: A sudden drop in event rate from an application that was previously active is itself a detection signal.

---

## 2. Agent & Control Channel Attack Surface

### Threat
The local enforcement agent is itself a target. An attacker who compromises the agent can:
- **Ignore containment commands**: Refuse to enforce session revocations or network blocks.
- **Exfiltrate signing keys**: Steal the Ed25519 private key and forge containment commands.
- **Replay old commands**: Re-execute expired containment actions.

### Current State
- Ed25519 signing is implemented with **mandatory TTLs** and **nonce-based replay protection**.
- The signing key is generated in-process at startup and held in memory. There is **no key distribution, rotation, or revocation mechanism**.
- The agent trusts the control plane's public key, but there is no mutual authentication.

### Unsolved Problems
- **Key distribution**: How do agents securely receive the control plane's public key at first contact? A compromised network could MitM this exchange.
- **Key rotation**: If the signing key is compromised, there is no mechanism to rotate it and invalidate old keys across all agents.
- **Key revocation**: There is no certificate revocation list or equivalent. A stolen key remains valid until the process restarts.
- **Agent integrity**: The agent itself runs as a library inside the application process (`crates/agent-sdk`). A compromised application can bypass the agent entirely. A standalone sidecar agent (Phase 7+) would improve isolation but isn't implemented.

---

## 3. Identity Resolution Errors

### Threat
The identity resolution layer merges heterogeneous identifiers (IP addresses, session tokens, user IDs, container IDs, PIDs) into unified entity nodes. Errors in this merging can have security consequences:
- **False merge**: Two unrelated actors are merged into one entity. Containment actions intended for one affect both. An innocent user gets their session revoked because their IP was shared with an attacker (NAT, shared infrastructure).
- **False split**: One actor appears as multiple entities. The system fails to correlate their activity across applications, and a multi-stage attack goes undetected.

### Current State
- Entity resolution uses deterministic rules: same IP + same session token = same entity. Same user ID across applications = same entity.
- There is **no confidence scoring** on identity merges.
- There is **no undo mechanism** for incorrect merges.
- IP-based correlation is inherently fragile in environments with NAT, shared proxies, or IPv6 privacy addresses.

### Mitigations (Planned)
- Confidence-weighted identity edges with a threshold below which merges are flagged but not committed.
- Operator-facing identity graph inspection (partially implemented in the dashboard) to manually verify suspicious merges.
- Prefer high-fidelity identifiers (user ID, session token) over low-fidelity ones (IP address) when building entity relationships.

---

## 4. In-Memory State Durability

### Threat
The correlation context graph, sliding-window rate counters, and incident state currently live entirely in memory. This means:
- **A restart loses all state**: Active incidents, entity relationships, and rate-tracking windows are lost. An attacker who can cause a control plane restart effectively resets the security system.
- **No horizontal scaling**: A single control plane instance is a throughput ceiling and a single point of failure for the security layer (though not for application availability, since the architecture is out-of-band).

### Current State
- `MemoryContextGraph`, `MemoryEventStream`, and `MemoryDurableSink` are all in-process, single-node data structures.
- Redis and PostgreSQL are in the architecture diagram but not yet integrated. The current system runs fully standalone with no external dependencies.

### Mitigations (Planned)
- Phase 7 introduces Redis for hot state (sliding windows, blacklists) and PostgreSQL for durable state (incidents, audit logs, filtered events).
- The `DurableEventSink` and `HotStateStore` traits are designed as abstractions specifically to allow swapping in-memory implementations for persistent backends without changing the security logic.
- Periodic state snapshots to disk could provide crash recovery even without external databases.

---

## 5. Detection Evasion

### Threat
The deterministic detection engine uses sliding-window counters and threshold-based rules. An attacker who understands the detection rules can:
- **Slow-play**: Stay below rate thresholds by spacing requests just outside the detection window.
- **Distribute across identities**: Use multiple IPs, sessions, or accounts to keep each entity below the threshold.
- **Exploit the detection-to-containment gap**: Act quickly and exfiltrate data before containment lands, since the architecture is detect-and-respond.

### Current State
- Detection rules are deterministic and threshold-based. They catch burst-pattern attacks reliably but are weaker against low-and-slow patterns.
- The cross-application correlation engine can detect distributed attacks *if* the identity resolution layer correctly merges the attacker's identities — which circles back to the identity resolution problem above.

### Mitigations (Planned)
- Behavioral baselines (planned, not implemented) that detect deviations from normal patterns rather than absolute thresholds.
- The Phase 6 advisory AI worker is designed to handle ambiguous, low-confidence signals that deterministic rules miss — but it is the lowest-priority phase.

---

## 6. Sensor-Specific Risks

### Tetragon
- Requires privileged access to the kernel. A compromised node with root access can disable or tamper with Tetragon.
- The control plane trusts Tetragon's output without independent verification.

### Falco
- Falco's syscall-based rules can be evaded by using less-monitored syscalls or by operating at a level Falco doesn't instrument.
- Alert fatigue from high false-positive rules can desensitize operators and degrade the correlation graph.

### Hubble
- Network flow data is metadata-only (L3/L4 headers, DNS labels). Encrypted payload content is not visible.
- In high-throughput clusters, flow sampling may cause dropped events that create blind spots.

### Current State
All three sensor adapters currently process **simulated payloads** modeled on real formats. The normalization logic is tested, but sensor-specific edge cases (malformed events, partial fields, high-volume bursts) have not been validated against real sensor output in a live cluster.

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
