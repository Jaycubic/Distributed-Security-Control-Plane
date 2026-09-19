# Distributed Security Control Plane — Master Architecture v2

## Current Project State

Phases 1 and 2 have been implemented and tested. The platform is currently an out-of-band security control plane for heterogeneous web applications.

The existing architecture separates normal application availability from security intelligence: normal application requests do not wait for security ingestion, correlation, detection, LLM analysis, or the security controller. The current plan already establishes Tetragon, Falco, and Cilium/Hubble as runtime/network telemetry sources; Redis as hot operational state; PostgreSQL as durable state; and deterministic Mode A as the default, with an optional off-path LLM Mode B. The implementation plan records Phases 1 and 2 as complete and Phase 3 as the next milestone.

---

# 1. Product Vision

Build a **high-performance, out-of-band Distributed Security Control Plane** that protects multiple heterogeneous web applications without forcing expensive security analysis into the synchronous application request path.

The system continuously observes application, runtime, kernel, and network telemetry; resolves identities and context; detects abnormal behavior; correlates events across applications; evaluates deterministic security policy; and rapidly orchestrates surgical containment when required.

The core philosophy is:

```text
NORMAL REQUEST PATH
Client
  |
  v
Application
  |
  +------------------> Response
  |
  +---- asynchronous telemetry ----> Security Control Plane
```

The security system is therefore **beside the application traffic path**, not an inline proxy for normal traffic.

---

# 2. Core Architectural Invariants

1. **Normal application requests must never wait for security ingestion, correlation, detection, LLM analysis, or the Security Control Plane.**
2. The Security Control Plane must not become a synchronous reverse proxy/gateway in the default architecture.
3. Security telemetry emission must be non-blocking/best-effort from the application perspective, with bounded queues and explicit backpressure behavior.
4. Redis is hot/volatile operational state; PostgreSQL is durable historical/institutional state.
5. High-volume raw telemetry must not automatically become one PostgreSQL row per event.
6. The Event Stream is the decoupling boundary between ingestion and downstream consumers.
7. Identity Resolution is a first-class security component before cross-application correlation.
8. Tetragon, Falco, and Hubble/Cilium are distinct telemetry sources; their source-specific semantics must be preserved.
9. The deterministic security core is the root of trust.
10. LLM functionality is **OFF by default**, optional, asynchronous, advisory, and never directly authorized to execute containment.
11. Every automated containment action must be attributable, time-bounded where appropriate, auditable, and reversible where technically feasible.
12. Performance targets are benchmark objectives, not assumed guarantees.
13. The Security Control Plane must not become a new single point of failure for normal application availability.

---

# 3. High-Level Architecture

```text
                         INTERNET / USERS
                                |
                                v
                     +-----------------------+
                     |   WEB APPLICATIONS    |
                     |                       |
                     | App A   App B   App C |
                     +-----------+-----------+
                                 |
                         NORMAL TRAFFIC
                                 |
                                 +----------------------> Response
                                 |
                          ASYNC TELEMETRY
                                 |
          +----------------------+----------------------+
          |                      |                      |
          v                      v                      v
     App Agents            Tetragon                  Hubble
     / Middleware             Falco                / Cilium
          |                      |                      |
          +----------------------+----------------------+
                                 |
                                 v
                     +-----------------------+
                     | Rust Ingestion Layer  |
                     | Validation / Auth     |
                     | Normalization         |
                     +-----------+-----------+
                                 |
                                 v
                     +-----------------------+
                     | Event Stream           |
                     | Redis Streams initially|
                     +-----------+-----------+
                                 |
               +-----------------+------------------+
               |                 |                  |
               v                 v                  v
       Identity Resolver     Detection          Durable Writer
               |                 |                  |
               v                 v                  v
         Context Model       Hot State          PostgreSQL
               |               Redis
               +-------+---------+
                       |
                       v
                Correlation Engine
                       |
                       v
                 Policy Engine
                       |
                       v
                Incident Engine
                       |
          +------------+-------------+
          |                          |
          v                          v
      Deterministic              Optional LLM
       Response                     Worker
          |                          |
          |                    advisory only
          +------------+-------------+
                       |
                       v
                 Response Validator
                       |
                       v
                 Signed Commands
                       |
                       v
                     Agents
                       |
                       v
               Local Enforcement
```

---

# 4. Technology Stack

| Layer | Technology | Purpose |
|---|---|---|
| Core control plane | Rust + Tokio + Axum | High-throughput asynchronous security services |
| Runtime telemetry | Cilium Tetragon | Process/runtime/kernel security events |
| Runtime detection | Falco | Rule-oriented runtime behavior detection |
| Network telemetry | Cilium + Hubble | Network identity/flow visibility |
| Hot operational state | Redis | Sliding windows, temporary state, queues/streams, revocation state |
| Durable history | PostgreSQL | Events requiring retention, incidents, policies, audit, evidence metadata |
| Event stream | Redis Streams initially | Decouple ingestion from consumers |
| Dashboard | React + TypeScript + Vite | Security operations and incident investigation |
| Metrics | Prometheus + Grafana | Latency, health, throughput, queue depth |
| Optional AI | Python worker + configurable LLM | Ambiguity resolution/investigation only |

---

# 5. Why Out-of-Band

An inline model places security infrastructure directly in the application path:

```text
Client -> Security Gateway -> Application -> Response
```

The chosen architecture is:

```text
Client ------------------------> Application ----------------> Response
                                    |
                                    +--------> Security Telemetry
                                                   |
                                                   v
                                          Security Control Plane
```

The objective is to avoid turning security analysis into a mandatory latency and availability dependency.

The system may still retain selective synchronous controls already provided by the application or infrastructure (for example, existing authentication, rate limiting, or emergency local enforcement). The central Security Control Plane is not the default synchronous decision point for ordinary application requests.

---

# 6. Performance Model

Performance must be measured empirically.

Do not claim a fixed `<100 us`, `<150 us`, or any other universal overhead without benchmarking the exact deployment.

Measure at minimum:

```text
Application baseline
Application + telemetry emitter
Application + normal security integration
```

and record:

- p50
- p95
- p99
- p99.9
- CPU overhead
- memory overhead
- queue depth
- dropped events

Separate:

```text
Application-path overhead

from

Security-plane processing latency
```

A central goal is that expensive correlation, durable persistence, behavioral analysis, and LLM work do not block normal requests.

---

# 7. Event Model

The unified event envelope should remain generic enough to support multiple event classes without assuming everything is an HTTP request.

Core fields may include:

```text
event_id
timestamp_ns
source.type
source.event_type
app_id
environment
principal / actor
identity references
session_id
request_id / trace_id
source address
network context
action
resource
result
risk signals
policy references
raw evidence reference
```

The event model should preserve source-specific details. A Tetragon `process_exec`, a Falco runtime alert, and a Hubble network flow must remain distinguishable after normalization.

---

# 8. Event Stream Architecture

The ingestion layer should not directly couple every downstream function to the network-facing API.

```text
Sensors / Agents
      |
      v
Ingestion + Validation
      |
      v
Event Stream
      |
      +----> Identity Resolution
      |
      +----> Detection
      |
      +----> Correlation
      |
      +----> Durable Writer
      |
      +----> Metrics / Operations
```

Redis Streams are appropriate initially. The abstraction should remain replaceable so that a higher-throughput event platform can be evaluated later if real workloads require it.

---

# 9. Storage Strategy

## Redis — operational memory

Redis stores state that primarily answers:

> **What is happening now?**

Examples:

- sliding-window counters;
- failed-login counters;
- temporary risk state;
- active session revocation state;
- recent correlation windows;
- short-lived IP/entity reputation;
- event streams/queues;
- containment broadcasts;
- temporary policy/cache state.

## PostgreSQL — durable memory

PostgreSQL stores:

> **What happened, what did we decide, and why?**

Examples:

- security-significant events;
- incidents;
- policies;
- policy versions;
- applications;
- identities;
- audit records;
- containment commands and history;
- analyst actions;
- LLM analyses;
- evidence metadata;
- incident timelines.

High-volume telemetry retention must be configurable and should support filtering, aggregation, sampling, or archival rather than forcing every event into the relational store.

---

# 10. Identity Resolution

Identity Resolution becomes a first-class component in Phase 3.

```text
Source IP
   |
   v
Device / Fingerprint
   |
   v
Session
   |
   v
User / Service Identity
   |
   v
Application
   |
   v
Container / Workload
   |
   v
PID / Process
```

Prefer strong correlation identifiers when available:

- request ID;
- trace ID;
- session ID;
- container ID;
- process ancestry;
- namespace;
- authenticated principal.

Timestamp correlation should be treated as a fallback rather than the sole source of identity linkage.

---

# 11. Detection Engine

The deterministic detection engine is the default security mechanism.

It should support:

### Rule-based detection

```text
IF failed_logins > threshold
AND time_window < threshold
THEN signal = CREDENTIAL_ABUSE
```

### Rate-based detection

```text
requests / minute
failures / minute
4xx / 5xx bursts
```

### Sequence detection

```text
failed login
  -> successful login
  -> privilege change
  -> sensitive access
  -> mass export
```

### Baseline deviation

```text
Normal behavior
      |
      v
Observed behavior
      |
      v
Deviation signal
```

Avoid weak/high-noise rules such as simplistic geographic velocity detection in the initial core. They can be added later as optional signals with explicit false-positive handling.

---

# 12. Risk and Signal Accumulation

Security events may produce weighted signals rather than directly producing destructive actions.

```text
Event
  |
  v
Signal
  |
  +-- severity
  +-- confidence
  +-- entity
  +-- decay
  |
  v
Rolling Risk State
  |
  v
Policy Decision
```

Risk scores should have transparent provenance: which signals contributed, which rules fired, how the score changed, and what policy threshold was reached.

---

# 13. Cross-Application Correlation

Phase 3 should correlate behavior across applications rather than treating each application as an isolated security island.

Example:

```text
Attacker / Actor
     |
     +--> App A: repeated login failures
     |
     +--> App A: successful authentication
     |
     +--> App B: privileged endpoint
     |
     +--> App C: bulk export
     |
     +--> Runtime: suspicious process execution
```

The correlation engine should build an in-memory context graph with TTLs and canonical identities.

Do not introduce a graph database until real workload/query requirements justify it.

---

# 14. Incident Lifecycle

```text
OBSERVE
   |
   v
DETECT
   |
   v
CORRELATE
   |
   v
ASSESS
   |
   v
CONTAIN
   |
   v
RECOVER
```

Every incident should preserve:

- timeline;
- evidence;
- affected applications/entities;
- triggered rules/signals;
- policy decisions;
- response actions;
- operator actions;
- recovery state.

---

# 15. Graduated Containment

Containment should be capability-oriented rather than only level-oriented.

```text
OBSERVE
  |
  v
ALERT
  |
  v
THROTTLE
  |
  v
REVOKE SESSION
  |
  v
LOCK IDENTITY
  |
  v
BLOCK NETWORK
  |
  v
ISOLATE WORKLOAD
```

Possible capabilities include:

```text
REVOKE_SESSION
THROTTLE_ACTOR
BLOCK_SOURCE
BLOCK_NETWORK_DESTINATION
REVOKE_CAPABILITY
RESTRICT_RESOURCE_ACCESS
ISOLATE_SERVICE
```

Containment should be proportional to confidence and evidence.

---

# 16. Signed Control Channel

Containment commands should travel over an authenticated control channel.

Each command should include concepts such as:

```text
command_id
incident_id
policy_id
target
action
issued_at
expires_at
nonce
policy_version
evidence_reference
authorization
```

Ed25519 signatures are an appropriate implementation candidate.

Agents verify:

1. authenticity;
2. integrity;
3. expiry;
4. replay protection;
5. target identity;
6. allowed action vocabulary;
7. local policy constraints.

The LLM does not get these privileges.

---

# 17. TTL and Rollback

Containment should be temporary where appropriate.

Example:

```text
BLOCK_SOURCE
expires_at = now + 15 minutes
```

Every action should have a defined rollback story where technically feasible.

The system should retain:

```text
Who/what initiated it?
Why?
Which incident?
Which policy?
What evidence?
When did it expire?
Was it reverted manually?
Did it fail?
```

---

# 18. Failure Model

The Security Control Plane must not become a single point of failure.

## Controller unavailable

```text
Application continues
        |
        +--> Agent buffers telemetry
        |
        +--> Cached emergency policies remain available
        |
        +--> Reconnect and replay
```

## Redis unavailable

Define explicit degraded behavior for hot-state dependent detection and event transport. Do not silently assume availability.

## PostgreSQL unavailable

Applications should normally continue. Security-significant durable events should follow a bounded buffering/retry policy.

## LLM unavailable

Fall back to deterministic Mode A.

## Agent disconnected

Central dashboard reports degraded agent health. Local behavior follows cached emergency policy and local safety rules.

Failure behavior should be defined per capability rather than as a single global "fail-open/fail-closed" switch.

---

# 19. Tetragon, Falco, and Cilium/Hubble

These technologies should remain separate sources of evidence.

## Tetragon

Study/use for process and runtime events including process execution/lifecycle and relevant kernel/network observations.

## Falco

Study/use for syscall/runtime behavior and rule-based security alerts.

## Cilium / Hubble

Study/use for network identity, service-to-service communication, and network flow visibility.

Preserve source fidelity:

```json
{
  "source": {
    "type": "tetragon",
    "event_type": "process_exec"
  }
}
```

is different from:

```json
{
  "source": {
    "type": "hubble",
    "event_type": "network_flow"
  }
}
```

---

# 20. Kernel-to-Application Correlation

The platform should connect low-level runtime observations to higher-level application context when evidence permits.

Example:

```text
HTTP request
   |
   v
Application request_id
   |
   +--> container_id
          |
          +--> PID
                 |
                 +--> process_exec: curl
                 |
                 +--> socket connect
```

The system should avoid pretending that every kernel event can be perfectly attributed to a single HTTP request. Correlation confidence and evidence provenance should be recorded.

---

# 21. Optional LLM Architecture

The platform has two explicit modes.

## Mode A — Default

```text
Event
  |
  v
Deterministic Detection
  |
  v
Policy
  |
  v
Response
```

No LLM dependency. No model latency. No model token cost.

## Mode B — Optional

```text
Event
  |
  v
Deterministic Engine
  |
  +--> known -> Response
  |
  +--> ambiguous -> LLM Worker
                         |
                         v
                    Structured JSON
                         |
                         v
                  Schema Validation
                         |
                         v
                Deterministic Policy Gate
                         |
                         v
                  Authorization / Approval
                         |
                         v
                    Signed Command
```

The LLM is an analyst/reasoner, not the security authority.

It may:

- summarize an incident;
- correlate evidence;
- identify hypotheses;
- classify ambiguous behavior;
- recommend a response.

It must not directly:

- execute shell commands;
- block network traffic;
- revoke sessions;
- isolate services;
- modify security policy.

---

# 22. Deno-Inspired Security Abstractions

Deno should be treated as a **study/reference implementation**, not as a mandatory dependency or as the new runtime for the platform.

Official repository:

https://github.com/denoland/deno

Official permission documentation:

https://docs.deno.com/runtime/reference/permissions/

Security documentation:

https://docs.deno.com/runtime/fundamentals/security/

Permission configuration:

https://docs.deno.com/runtime/reference/deno_json/

Relevant source areas to inspect:

https://github.com/denoland/deno/tree/main/cli

https://github.com/denoland/deno/tree/main/runtime

https://github.com/denoland/deno/tree/main/ext

The purpose is to study Deno's capability/permission abstractions and determine which concepts improve this project's policy engine.

## 22.1 Capability-Oriented Permissions

Study the concept of a sensitive action requiring an explicitly granted capability.

Adapt conceptually to:

```text
Capability
├── principal
├── action
├── resource
├── scope
├── conditions
├── issued_at
├── expires_at
└── status
```

Potential capabilities:

```text
database.read
database.write
network.connect
filesystem.read
filesystem.write
process.execute
admin.operation
```

## 22.2 Scoped Permissions

Avoid generic:

```text
network = allowed
```

Prefer:

```text
ALLOW postgres.internal:5432
DENY *
```

or:

```text
ALLOW /app/storage/**
DENY /etc/**
```

This supports least privilege and surgical containment.

## 22.3 Explicit Allow and Deny

Study Deno's explicit allow/deny model and adopt a deterministic precedence rule.

A proposed policy abstraction:

```text
ALLOW capability/resource
DENY capability/resource
DENY takes precedence
```

This must be deterministic, testable, and explainable.

## 22.4 Runtime Permission State

Study the distinction between current permission state and static configuration.

Adapt to:

```text
GRANTED
DENIED
RESTRICTED
REVOKED
```

This creates a direct bridge between policy and containment.

Example:

```text
Normal:
    application may access db-A

Incident:
    revoke database.read

Recovery:
    restore only after policy/approval
```

## 22.5 Declarative Policy Bundles

Create human-readable, versioned policy bundles.

Example:

```yaml
policy:
  id: app-a-production-v4

allow:
  network:
    - postgres.internal:5432
  filesystem:
    - /app/storage/**

deny:
  network:
    - "*"
  process:
    - /bin/sh
    - curl
    - wget
```

Policies should be:

- versioned;
- auditable;
- testable;
- integrity-protected;
- reloadable;
- scoped;
- rollback-capable.

## 22.6 Policy Decision Explainability

Every authorization/policy result should answer:

```text
WHO?
WHAT ACTION?
ON WHICH RESOURCE?
UNDER WHICH POLICY?
WHY ALLOWED?
WHY DENIED?
WHAT EVIDENCE?
WHEN?
```

This should appear in the dashboard and persist in audit records.

## 22.7 Capability Revocation

Containment should eventually support capability reduction, not only workload termination.

Potential actions:

```text
REVOKE_CAPABILITY
RESTRICT_NETWORK_SCOPE
RESTRICT_FILESYSTEM_SCOPE
RESTRICT_PROCESS_EXECUTION
REVOKE_RESOURCE_ACCESS
```

These actions must only be enabled where the protected application/integration has a trustworthy enforcement mechanism.

## 22.8 Policy Simulation / Dry Run

Policies should be testable against recorded events before enforcement:

```text
EVENT
  |
  v
POLICY SIMULATION
  |
  +--> WOULD ALLOW
  +--> WOULD DENY
  +--> WOULD THROTTLE
  +--> WOULD REVOKE_CAPABILITY
```

## 22.9 Policy Regression Tests

Policies should have machine-testable expected behavior:

```text
Given:
    actor=service-A
    action=network.connect
    target=db-A:5432

Expected:
    ALLOW
```

and:

```text
Given:
    actor=service-A
    action=network.connect
    target=external.example:443

Expected:
    DENY
```

---

# 23. What NOT to Take from Deno

Do not turn the project into a Deno reimplementation.

Do not:

- make Deno a required runtime dependency;
- replace Rust/Tokio with Deno;
- copy large amounts of Deno implementation without a concrete requirement;
- assume Deno's permission model maps perfectly to every server environment;
- let protected workloads self-grant capabilities.

Deno is being used as an architectural reference for **capability security, scoped authorization, permission state, and declarative policy**.

---

# 24. Project Phase Status

## Phase 1 — COMPLETE

Architecture core, unified event schema, ingestion foundation, event stream abstraction, asynchronous application emitters, dual-tier state, and initial dashboard have been implemented and tested.

## Phase 2 — COMPLETE

Hot-state engine and deterministic detection have been implemented and tested, including sliding windows, deterministic rules, signal accumulation, risk scoring, incidents, and the related operations interface.

## Phase 3 — NEXT

### Identity Resolution + Multi-Application Correlation + Capability Context

Primary deliverables:

- canonical entity resolution;
- identity graph;
- IP/session/user/application/workload/process linkage;
- cross-application attack-chain correlation;
- capability/resource context;
- policy-decision context;
- explainable correlation evidence.

Do not introduce a graph database unless real workload analysis demonstrates the need.

## Phase 4

### Graduated Containment + Capability Revocation

Deliver:

- capability-oriented actions;
- signed control channel;
- TTLs;
- rollback;
- local policy cache;
- policy simulation;
- containment audit trail.

## Phase 5

### Tetragon + Falco + Cilium/Hubble

Deliver:

- source-specific adapters;
- preserved telemetry semantics;
- kernel/runtime/network correlation;
- application context linkage.

## Phase 6

### Optional LLM Investigation

Default remains OFF.

Deliver:

- incident review queue;
- structured outputs;
- investigation summaries;
- hypothesis generation;
- deterministic validation;
- approval workflow;
- no direct execution privileges.

## Phase 7

### Production Hardening, Observability, Benchmarking, Packaging

Deliver:

- fault injection;
- load testing;
- security testing;
- policy regression testing;
- incident replay;
- dashboards;
- packaging;
- recovery/runbooks;
- measured performance evidence.

---

# 25. Revised Phase 3 Direction

Because Phases 1 and 2 are complete, Phase 3 should prioritize **context and authorization semantics** rather than simply adding more detection rules.

Target flow:

```text
Raw Event
    |
    v
Normalize
    |
    v
Identity Resolution
    |
    v
Canonical Entity
    |
    v
Capability / Resource Context
    |
    v
Cross-App Correlation
    |
    v
Attack Chain / Context Graph
    |
    v
Deterministic Detection
    |
    v
Policy Decision
```

The Deno-inspired work belongs primarily here and in Phase 4.

---

# 26. Operations Dashboard

The dashboard should eventually show:

### Overview

- applications;
- agent health;
- event throughput;
- active incidents;
- active containment;
- policy violations.

### Incidents

- incident timeline;
- affected entities;
- correlation graph;
- triggered signals;
- evidence;
- policy decisions;
- response actions.

### Policies

- policy versions;
- allow/deny rules;
- capability definitions;
- simulation mode;
- activation/rollback.

### Containment

- active actions;
- TTL;
- evidence;
- status;
- rollback;
- operator history.

### Sensors

- Tetragon health;
- Falco health;
- Hubble health;
- event rates;
- dropped/rejected events.

---

# 27. Testing Strategy

Security infrastructure must be tested as a system, not only through unit tests.

## Unit tests

- event serialization/deserialization;
- policy evaluation;
- allow/deny precedence;
- sliding windows;
- risk decay;
- identity resolution;
- correlation edges;
- signature validation;
- TTL calculations.

## Integration tests

- application agent → ingestion;
- ingestion → event stream;
- stream → detector;
- detector → incident;
- incident → policy;
- policy → signed command;
- agent → local enforcement.

## Adversarial tests

Test:

- malformed telemetry;
- spoofed events;
- replayed commands;
- oversized events;
- event floods;
- stale policies;
- conflicting policies;
- false-positive scenarios;
- controller outage;
- Redis outage;
- PostgreSQL outage;
- agent outage;
- LLM outage.

## Incident replay

Every incident should be replayable against a newer detector/policy version to test whether decisions change.

---

# 28. Security of the Security Platform

The Security Control Plane becomes highly privileged infrastructure.

Therefore:

- least privilege is mandatory;
- sensor inputs are treated as untrusted data;
- telemetry producers authenticate;
- response commands are signed;
- dashboard actions are authorized;
- LLM worker has no infrastructure control credentials;
- policies are versioned and integrity-protected;
- privileged operations are audited;
- containment commands have replay protection;
- local agents enforce an explicit action vocabulary.

The system itself must be treated as a high-value security target.

---

# 29. Future Expansion Boundary: AI-Agent Protection

AI-agent runtime security is deliberately **not part of the current product scope**.

The architecture should, however, avoid hard-coding web-specific concepts into the core event, identity, capability, and policy models.

Future protected workload types may include:

```text
Web Application
Service
Worker
Autonomous AI Agent
Agent Tool Runtime
MCP Client/Server
Autonomous Task Runner
```

A future agent security extension could model:

```text
User
  |
  v
Agent
  |
  v
Task
  |
  v
Tool
  |
  v
Resource
```

Potential future agent capabilities:

```text
tool.call
filesystem.read
filesystem.write
shell.execute
network.connect
database.query
browser.navigate
secret.access
agent.delegate
```

This is intentionally deferred until the web-application security platform is mature.

---

# 30. Development Principle

Do not attempt to implement the entire product as one enormous task.

Build through vertical slices:

```text
Observe
   |
   v
Detect
   |
   v
Correlate
   |
   v
Contain
   |
   v
Recover
```

Each slice must be:

- executable;
- testable;
- benchmarked;
- observable;
- documented;
- reversible.

The goal is to produce a reliable security engine first and expand its capabilities without repeatedly redesigning its foundations.

---

# 31. Implementation Instruction for Antigravity

Before starting Phase 3 implementation:

1. Inspect the actual Phase 1 and Phase 2 implementation and tests. Do not assume the existing documentation is complete.
2. Read this master document fully.
3. Review the Deno repository and official permission/security documentation listed above.
4. Identify concrete Deno-inspired abstractions that improve the existing policy engine.
5. Produce an architecture delta for Phase 3 before writing significant code.
6. Preserve Phase 1 and Phase 2 behavior and public interfaces unless a change is justified and tested.
7. Keep the default runtime completely LLM-free.
8. Keep the normal application request path independent from the Security Control Plane.
9. Do not add AI-agent security to the current milestone.
10. Do not copy Deno implementation wholesale; use Deno as a study/reference source.
11. Do not introduce new infrastructure components merely because they are fashionable; justify each component against measured requirements.
12. Add regression tests for policy precedence, capability scope, revocation, simulation, and cross-application identity resolution.
13. Benchmark before claiming latency/performance properties.

The immediate objective is to make the existing platform **more capability-aware, explainable, policy-driven, and surgically containable** while retaining its out-of-band architecture.

---

# 32. Reference Sources

## Deno

- Repository: https://github.com/denoland/deno
- Security: https://docs.deno.com/runtime/fundamentals/security/
- Permissions: https://docs.deno.com/runtime/reference/permissions/
- Permission configuration: https://docs.deno.com/runtime/reference/deno_json/

## Runtime / Network Security

- Tetragon: https://github.com/cilium/tetragon
- Falco: https://github.com/falcosecurity/falco
- Cilium: https://github.com/cilium/cilium
- Hubble: https://github.com/cilium/hubble

---

# Final Principle

The product is fundamentally a **Distributed Runtime Security Control Plane for heterogeneous web applications**.

Its security intelligence operates beside normal traffic:

```text
Application
   |
   +--------------------> Response
   |
   +--------------------> Security Telemetry
                                  |
                                  v
                          Observe -> Detect
                                  -> Correlate
                                  -> Assess
                                  -> Contain
                                  -> Recover
```

Its deterministic core remains authoritative.

Its LLM is optional and OFF by default.

Its policy model should increasingly become capability-oriented and explicit.

Its runtime observation is strengthened by mature technologies such as Tetragon, Falco, and Cilium/Hubble.

Its architecture is deliberately extensible so that future workload types can be added without compromising the current web-application security product.
