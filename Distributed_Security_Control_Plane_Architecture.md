# Distributed Security Control Plane
## Out-of-Band Security Monitoring, Detection, Correlation, and Threat Containment for Multiple Web Applications

**Status:** Architecture / Engineering Proposal  
**Version:** 1.0  
**Document Type:** System Design / Technical Design Specification  
**Primary Goal:** Protect multiple existing web applications through centralized security intelligence and rapid containment without placing expensive security analysis on the synchronous application request path.

---

# 1. Executive Summary

This proposal defines a **Distributed Security Control Plane** for organizations running multiple web applications that already possess their own authentication, authorization, validation, logging, and application-level security controls.

The central idea is deliberately different from a conventional inline gateway or Web Application Firewall (WAF).

Instead of forcing every request through a centralized security engine before the application responds, applications continue operating normally while a lightweight security agent emits telemetry asynchronously to a private security control plane.

The security control plane then:

- collects security telemetry from many applications;
- normalizes and enriches events;
- correlates activity across applications;
- detects abnormal behavior and attack sequences;
- maintains security policies and risk state;
- creates incidents;
- initiates containment when a threat becomes sufficiently credible;
- pushes emergency policy or response actions back to local agents;
- alerts administrators;
- preserves evidence for investigation and recovery.

The fundamental design principle is:

> **Do not put the security brain in the critical request path. Observe continuously, detect centrally, correlate behavior across systems, and contain compromised activity rapidly when necessary.**

---

# 2. Problem Statement

An organization may operate several web applications:

```text
Application A
Application B
Application C
Application D
```

Each application may independently implement:

- authentication;
- authorization;
- sessions;
- API validation;
- rate limiting;
- input validation;
- logging;
- database security;
- application-specific workflows.

This creates several problems.

## 2.1 Inconsistent security maturity

One application may have strong controls while another has weaker or incomplete controls.

## 2.2 Security fixes become application-specific

Hardening three, five, ten, or twenty applications independently becomes expensive and operationally inconsistent.

## 2.3 Local visibility is incomplete

An individual application may see an event as normal while a centralized system can recognize a larger attack pattern.

For example:

```text
Application A:
    successful login

Application B:
    API access

Application C:
    database export
```

Individually these events may appear unrelated.

Centrally, they may belong to the same actor, session, source, credential, or attack chain.

## 2.4 Inline security can affect latency

Routing every request through a heavy analysis layer introduces additional processing, network hops, contention, and a possible availability dependency.

The proposed architecture therefore separates **application availability** from **security intelligence**.

---

# 3. Design Objectives

The platform should satisfy the following objectives.

## 3.1 Minimal request-path overhead

Normal application requests should not wait for centralized security analysis.

## 3.2 Centralized visibility

A single control plane should understand behavior across multiple applications and infrastructure components.

## 3.3 Behavioral detection

The system should identify suspicious sequences rather than relying only on single-event signatures.

## 3.4 Threat containment

Once suspicious activity reaches a sufficient confidence level, the platform should be able to restrict or isolate the affected identity, source, session, service, or application.

## 3.5 Failure tolerance

Loss of the central security system should not unnecessarily take applications offline.

## 3.6 Auditability

Every detection, policy decision, containment action, and administrative override should be traceable.

## 3.7 Application independence

The platform should work with heterogeneous applications such as FastAPI, Django, Node.js, Go, Java, and other services.

---

# 4. Core Architectural Decision

The architecture deliberately separates security processing into two planes.

```text
                    SECURITY ARCHITECTURE

       ┌───────────────────────────────┐
       │         DATA PLANE            │
       │                               │
       │ Client → Application → DB     │
       │                               │
       │ Fast / normal / independent   │
       └───────────────┬───────────────┘
                       │
                  async telemetry
                       │
                       ▼
       ┌───────────────────────────────┐
       │       SECURITY CONTROL        │
       │             PLANE             │
       │                               │
       │ Ingestion                     │
       │ Correlation                   │
       │ Detection                     │
       │ Policy                        │
       │ Incident Response             │
       │ Alerting                      │
       └───────────────────────────────┘
```

### Data Plane

Handles normal application traffic.

### Security Control Plane

Handles telemetry, intelligence, detection, policy, investigation, and response.

The control plane should generally **not sit synchronously between the client and the application**.

---

# 5. Inline Gateway vs Out-of-Band Security

## 5.1 Inline architecture

```text
Client
  │
  ▼
Security Gateway
  │
  ▼
Application
  │
  ▼
Response
```

Advantages:

- immediate request blocking;
- direct inspection;
- centralized enforcement.

Disadvantages:

- every request pays gateway processing cost;
- gateway availability becomes critical;
- complex inspection can increase tail latency;
- a failure can affect every application.

## 5.2 Proposed out-of-band architecture

```text
Client
  │
  ▼
Application ───────────────► Response
  │
  └──── asynchronous event ─────► Security Plane
```

Advantages:

- extremely small request-path overhead;
- detection can be computationally expensive without delaying users;
- cross-application correlation becomes natural;
- controller failure does not automatically stop applications;
- security capabilities can evolve independently from application code.

Disadvantages:

- some malicious actions may occur before detection;
- prevention of an individual request is weaker than a fully inline security layer;
- telemetry quality becomes critical;
- response mechanisms must be designed carefully.

This proposal intentionally chooses **low-latency operation + strong detection + rapid containment**.

---

# 6. Why the System Focuses on Threat Spread / Containment

A central design insight is that not every malicious event can be stopped before execution without introducing an inline dependency.

Instead, the platform focuses strongly on limiting what happens **after suspicious behavior emerges**.

Example:

```text
09:00:00.000  attacker → DELETE /users/123
09:00:00.001  application executes request
09:00:00.010  telemetry reaches security system
09:00:00.050  detection identifies malicious sequence
09:00:00.080  containment policy issued
09:00:00.100  session revoked / account disabled
```

The DELETE may not have been preventable through the out-of-band plane.

However, the architecture attempts to prevent:

```text
one malicious action
        ↓
continued access
        ↓
mass actions
        ↓
lateral movement
        ↓
spread across applications
```

The system therefore emphasizes **containment, blast-radius reduction, and rapid response**.

---

# 7. High-Level Architecture

```text
                                  INTERNET
                                     │
                                     ▼
                           ┌───────────────────┐
                           │  Existing Edge    │
                           │ Firewall / LB /   │
                           │ Reverse Proxy     │
                           └─────────┬─────────┘
                                     │
                  ┌──────────────────┼──────────────────┐
                  │                  │                  │
                  ▼                  ▼                  ▼
             Application A     Application B     Application C
                  │                  │                  │
               Agent A             Agent B             Agent C
                  │                  │                  │
                  └──────────────────┼──────────────────┘
                                     │
                              Async telemetry
                                     │
                                     ▼
                       ┌───────────────────────────┐
                       │ Security Ingestion Layer │
                       └─────────────┬─────────────┘
                                     │
                                     ▼
                       ┌───────────────────────────┐
                       │ Event Normalization      │
                       └─────────────┬─────────────┘
                                     │
                                     ▼
                       ┌───────────────────────────┐
                       │ Correlation Engine       │
                       └─────────────┬─────────────┘
                                     │
                                     ▼
                       ┌───────────────────────────┐
                       │ Detection Engine          │
                       └─────────────┬─────────────┘
                                     │
                                     ▼
                       ┌───────────────────────────┐
                       │ Policy / Risk Engine      │
                       └─────────────┬─────────────┘
                                     │
                                     ▼
                       ┌───────────────────────────┐
                       │ Incident / Response       │
                       └─────────────┬─────────────┘
                                     │
                    ┌────────────────┼────────────────┐
                    │                │                │
                    ▼                ▼                ▼
                 Alerts          Agent A          Agent B/C
                                     │
                                     ▼
                              Local containment
```

---

# 8. Security Agent

Each protected application should have a lightweight **Security Agent** or equivalent integration layer.

```text
┌────────────────────────────────────────────┐
│ Application Host / Container               │
│                                            │
│  ┌──────────────────────────────────────┐  │
│  │ Application                          │  │
│  └──────────────────┬───────────────────┘  │
│                     │                      │
│  ┌──────────────────▼───────────────────┐  │
│  │ Security Agent                       │  │
│  │                                      │  │
│  │ Event collector                      │  │
│  │ Event normalization                  │  │
│  │ Local queue / buffer                 │  │
│  │ Policy cache                         │  │
│  │ Emergency enforcement                │  │
│  └──────────────────┬───────────────────┘  │
└─────────────────────┼──────────────────────┘
                      │
                      ▼
              Security Controller
```

The agent should remain intentionally small and deterministic.

It should **not** perform expensive ML analysis or global correlation.

Primary responsibilities:

1. Capture relevant events.
2. Normalize events into the common schema.
3. Attach metadata and correlation IDs.
4. Place telemetry into a local queue.
5. Transmit asynchronously.
6. Buffer during controller outages.
7. Cache emergency policies.
8. Validate and execute authorized containment commands.

---

# 9. Event Model

Security telemetry should be structured rather than treated as arbitrary log text.

Example event:

```json
{
  "event_id": "evt_123",
  "timestamp": "2026-09-18T10:30:00Z",
  "application": "Application-A",
  "environment": "production",
  "event_type": "authentication.login",
  "actor": {
    "user_id": "user_123",
    "role": "admin"
  },
  "source": {
    "ip": "10.20.30.40"
  },
  "action": {
    "success": true
  },
  "resource": null,
  "request_id": "req_456",
  "session_id": "sess_789"
}
```

Important fields may include:

- event ID;
- timestamp;
- application;
- environment;
- actor identity;
- source identity;
- device/session identity;
- request ID;
- event type;
- operation;
- resource;
- outcome;
- risk classification;
- correlation identifiers.

Sensitive request bodies, passwords, access tokens, and private data should not automatically be copied into the security plane.

---

# 10. Telemetry Categories

## 10.1 Network telemetry

- source/destination;
- connection creation;
- connection rate;
- protocol;
- port;
- unusual destinations.

## 10.2 HTTP/API telemetry

- HTTP method;
- endpoint;
- route template;
- status code;
- response size;
- latency;
- authenticated identity;
- API token identifier (non-secret);
- request rate.

## 10.3 Authentication telemetry

- login;
- logout;
- failed login;
- password changes;
- MFA success/failure;
- session creation;
- token creation/revocation.

## 10.4 Authorization telemetry

- access granted;
- access denied;
- privilege changes;
- role changes;
- administrative actions.

## 10.5 Application telemetry

- business operations;
- exports;
- configuration changes;
- sensitive workflow transitions;
- file operations;
- unusual job execution.

## 10.6 Database telemetry

- sensitive resource access;
- mass reads;
- mass writes;
- administrative changes;
- schema changes;
- abnormal query patterns.

## 10.7 Host/container telemetry

- process creation;
- service changes;
- filesystem changes;
- container lifecycle;
- network connections;
- unexpected execution.

---

# 11. Normal Request Flow

The normal request path should remain simple:

```text
Client
  │
  ▼
Application
  │
  ├──────────────► Business logic
  │                    │
  │                    ▼
  │                 Database
  │                    │
  ▼                    ▼
Response ◄─────────────┘

Application
   │
   └────► local event queue ─────► Security Plane
```

The application should not wait for:

- central event persistence;
- detection;
- correlation;
- ML inference;
- security dashboard updates.

---

# 12. Performance Strategy

Performance is a first-class design requirement.

If an isolated application responds in approximately 2 ms, the goal is to make the security telemetry path contribute only a very small amount of work to the synchronous path.

A literal **0 ms** additional cost is not physically achievable when additional work is performed, but the synchronous security cost can be made very small and bounded by keeping expensive work asynchronous.

## 12.1 Do not perform this on the hot path

```text
Request
  │
  ▼
Security Analysis
  │
  ▼
Database Lookup
  │
  ▼
ML Inference
  │
  ▼
Correlation
  │
  ▼
Application
```

## 12.2 Prefer this

```text
Request
  │
  ├──────────────► Application ───► Response
  │
  └──────────────► Local event queue
                           │
                           ▼
                    Security pipeline
```

---

# 13. Latency Budget

Measure in microseconds, not only milliseconds.

```text
1 ms = 1,000 µs
```

A design target might look like:

```text
Event creation / metadata     < 50 µs
Local queue operation         < 50 µs
Minimal synchronization       < 50 µs
--------------------------------------
Target synchronous overhead   < 150 µs
```

These are engineering targets, not universal guarantees.

The actual system must benchmark the deployed topology.

---

# 14. Tail Latency, Not Average Latency

Do not evaluate the platform using only average latency.

Measure:

```text
p50
p90
p95
p99
p99.9
```

An illustrative engineering SLO could be:

```text
Gateway / agent synchronous overhead

p50   < 0.2 ms
p95   < 0.5 ms
p99   < 1.0 ms
p99.9 < 2.0 ms
```

These values are proposed **targets for engineering evaluation**, not claims of guaranteed performance.

---

# 15. Keep the Hot Path Memory-Resident

Do not perform database work for every request merely to decide whether the event should be recorded.

Prefer:

```text
CPU cache
   ↓
RAM
   ↓
local hash tables
   ↓
lock-free or low-contention queues
```

Central persistence can happen in batches.

For example:

```text
100 events
      │
      ▼
local batch
      │
      ▼
network transmission
      │
      ▼
security ingestion
```

---

# 16. Local Queue and Backpressure

The local agent should protect application performance when the central controller is slow or unavailable.

```text
Application
    │
    ▼
Local Queue
    │
    ├── controller healthy → transmit
    │
    └── controller unavailable → buffer
```

The queue should have clear limits:

- maximum events;
- maximum bytes;
- retention period;
- disk vs memory thresholds;
- drop/degrade policy.

Security telemetry should never be allowed to exhaust application memory or disk.

---

# 17. Event Delivery Guarantees

A practical design should aim for **at-least-once telemetry delivery** for important events.

```text
Application
    │
    ▼
Durable Local Queue
    │
    ▼
Security Controller
```

If the controller is unavailable:

```text
Events
  │
  ▼
Local durable queue
  │
  │ controller DOWN
  │
  └────► retained
```

When the controller returns:

```text
retained events
      │
      ▼
replay
      │
      ▼
controller
```

Important events should carry an event ID so ingestion can be idempotent.

---

# 18. Detection Engine

The detection layer should support progressively more sophisticated methods.

## 18.1 Rule-based detection

Example:

```text
IF
    failed_login_count > 10
    within 5 minutes
THEN
    raise authentication anomaly
```

## 18.2 Rate detection

```text
Normal:
20 requests/minute

Observed:
900 requests/minute

→ anomaly
```

## 18.3 Baseline detection

```text
Typical user behavior:
    /dashboard
    /profile
    /records

Observed:
    /admin/export

→ deviation from baseline
```

## 18.4 Sequence detection

```text
failed login
      +
successful login
      +
privilege change
      +
mass record read
      +
large export
      =
high-risk sequence
```

---

# 19. Behavioral Detection

The security platform should model **normal behavior** and identify meaningful deviations.

Example:

```text
Normal user
 ├── 1-5 logins/day
 ├── 10-100 API requests/min
 ├── reads a small number of records
 └── uses stable routes
```

Observed behavior:

```text
Same identity
 ├── 60 failed logins
 ├── successful login from unusual source
 ├── 2,000 API requests/min
 ├── sequential record enumeration
 └── 40,000 records exported
```

The system should not require any single event to be malicious.

It can assign evidence and accumulate a risk score over time.

---

# 20. Correlation Engine

Correlation is one of the highest-value components of the platform.

```text
Application A       Application B       Application C
     │                    │                    │
     └──────────────┬─────┴─────┬─────────────┘
                    │           │
                    ▼           ▼
                 source      identity
                    │           │
                    └─────┬─────┘
                          ▼
                   Correlation graph
                          │
                          ▼
                   Single incident
```

Possible correlation dimensions:

- user identity;
- source IP;
- device identity;
- session ID;
- token ID;
- API key ID;
- service identity;
- host;
- container;
- application;
- time window;
- database account;
- request ID.

---

# 21. Security Context Graph

The control plane can maintain a logical relationship graph:

```text
                 ┌──────────────┐
                 │   Identity   │
                 └──────┬───────┘
                        │
          ┌─────────────┼─────────────┐
          │             │             │
          ▼             ▼             ▼
       Session        Device         Token
          │
          ▼
      Application
          │
          ▼
        API Route
          │
          ▼
        Resource
          │
          ▼
       Database
```

This graph allows the platform to reason about an incident beyond individual log lines.

---

# 22. Incident Lifecycle

```text
OBSERVE
   │
   ▼
DETECT
   │
   ▼
CORRELATE
   │
   ▼
ASSESS
   │
   ▼
CONTAIN
   │
   ▼
RECOVER
   │
   ▼
LEARN
```

## Observe

Collect telemetry.

## Detect

Identify anomalies or rule violations.

## Correlate

Connect related evidence.

## Assess

Estimate confidence and potential impact.

## Contain

Limit ongoing activity.

## Recover

Restore normal service and credentials.

## Learn

Improve rules, policies, and baselines.

---

# 23. Risk and Confidence Model

A detection does not necessarily equal an incident.

The platform should distinguish:

```text
Event
  ↓
Signal
  ↓
Anomaly
  ↓
Correlated suspicion
  ↓
Incident
  ↓
Containment
```

Example evidence accumulation:

```text
+1  failed login burst
+2  successful login after burst
+2  abnormal source
+3  privilege change
+5  mass data access
+5  large export
----------------------
18  total risk evidence
```

The exact scoring system should be configurable.

A score should not be treated as an absolute truth; it is an aid for policy decisions.

---

# 24. Response Levels

Containment should be graduated rather than immediately destructive.

```text
LEVEL 0
Normal monitoring

LEVEL 1
Increase telemetry

LEVEL 2
Generate alert

LEVEL 3
Restrict suspicious session / identity

LEVEL 4
Block source / credential / token

LEVEL 5
Isolate affected service

LEVEL 6
Emergency shutdown / quarantine
```

The system should explicitly support policy-controlled escalation.

---

# 25. Response Engine

The response engine translates security decisions into actions.

```text
Detection
   │
   ▼
Incident
   │
   ▼
Response Policy
   │
   ├── revoke session
   ├── disable account
   ├── block source
   ├── disable token
   ├── restrict route
   ├── isolate service
   ├── preserve evidence
   └── alert administrator
```

Actions should be explicit, auditable, and reversible where possible.

---

# 26. Local Enforcement

A lightweight agent can perform immediate local response.

```text
Security Controller
        │
        │ secure command
        ▼
Local Agent
        │
        ├── revoke session
        ├── apply emergency block
        ├── restrict access
        ├── stop sensitive workflow
        └── isolate service
```

The central system makes the intelligence-heavy decision.

The local agent performs the low-latency enforcement.

---

# 27. Secure Control Channel

The control channel is highly privileged and must be strongly protected.

A response command can conceptually contain:

```json
{
  "command_id": "cmd_1042",
  "target": "application-A",
  "action": "REVOKE_SESSION",
  "issued_at": "2026-09-18T10:30:00Z",
  "expires_at": "2026-09-18T10:35:00Z",
  "policy_version": 42,
  "nonce": "...",
  "signature": "..."
}
```

Agent validation should include:

1. authenticity;
2. authorization;
3. target identity;
4. expiry;
5. replay protection;
6. permitted action;
7. local safety constraints.

---

# 28. Preventing Command Abuse

The security controller becomes a high-trust system.

Compromise of the controller could potentially affect multiple applications.

Therefore:

- agent identities must be unique;
- control messages must be authenticated;
- privileged commands must be authorized;
- commands should be signed or otherwise cryptographically authenticated;
- commands should expire;
- replay should be prevented;
- every action must be logged;
- administrative operations should be strongly protected;
- policy changes should be versioned.

---

# 29. Failure Model

A central principle is:

> **Security analysis failure should not automatically become application failure.**

Normal controller outage:

```text
Security Controller DOWN
        │
        ▼
Application continues
        │
        ├── local telemetry continues
        ├── events buffered
        └── cached emergency policies remain available
```

Controller recovery:

```text
Controller returns
      │
      ▼
agent reconnects
      │
      ▼
buffered events replay
      │
      ▼
normal operation
```

---

# 30. Fail-Open vs Fail-Closed

The platform should distinguish between two different failures.

## Observation failure

The analysis service is unavailable.

Default behavior:

```text
Application continues
```

## Explicit emergency policy

A local agent already possesses an authorized emergency policy.

Example:

```text
IF token == revoked
THEN deny request
```

or:

```text
IF application isolation policy active
THEN deny external ingress
```

In these specific cases, local enforcement can continue even if the controller is temporarily unavailable.

---

# 31. Application Integration Modes

The system should support several integration strategies.

## 31.1 SDK

```text
Application
   │
Security SDK
   │
Agent
```

Useful for application-specific business events.

## 31.2 Middleware

Automatically collect:

- endpoint;
- method;
- status;
- identity;
- latency;
- request ID.

## 31.3 Infrastructure telemetry

Collect:

- process data;
- container lifecycle;
- network activity;
- filesystem activity.

## 31.4 Database telemetry

Collect relevant database security events where technically and legally appropriate.

A mature system can combine all four.

---

# 32. Privacy and Data Minimization

Security telemetry should follow a **minimum necessary information** principle.

Avoid automatically transmitting:

- passwords;
- session secrets;
- access tokens;
- private keys;
- full sensitive request bodies;
- full database records.

Prefer metadata:

```text
operation = READ
resource = /patients/123
classification = sensitive
identity = user_123
result = success
```

rather than copying the patient record itself.

---

# 33. Security Event Store

A central event store can support:

```text
security_events
----------------
event_id
timestamp
application
environment
event_type
actor_id
source_id
session_id
request_id
resource
outcome
risk_evidence
```

Separate incident data from raw telemetry where useful.

```text
Event Store
Incident Store
Policy Store
Agent Registry
Audit Store
```

---

# 34. Control Plane Components

A production-oriented system can be divided into:

```text
security-agent
security-ingestion
security-normalizer
security-event-store
security-correlation-engine
security-detection-engine
security-policy-engine
security-risk-engine
security-incident-engine
security-response-engine
security-alerting
security-admin-ui
```

A small implementation can combine several of these modules.

---

# 35. Minimal Viable Product

Do not start with ML, distributed tracing, and sophisticated response orchestration all at once.

A strong MVP is:

```text
Application
   │
   ▼
Security Agent
   │
   ▼
Ingestion API
   │
   ▼
Event Store
   │
   ▼
Rule Engine
   │
   ▼
Alert
```

Then add:

```text
Correlation
    │
    ▼
Incident Engine
    │
    ▼
Response Engine
    │
    ▼
Local Agent Enforcement
```

Only after this is reliable should more advanced behavioral models be introduced.

---

# 36. Development Roadmap

## Phase 1 — Telemetry Foundation

Build:

- agent;
- event schema;
- queue;
- ingestion API;
- event storage;
- basic dashboard.

Goal:

> Establish centralized visibility.

## Phase 2 — Deterministic Detection

Build:

- failed-login rules;
- rate anomalies;
- privilege-change rules;
- sensitive-resource rules.

Goal:

> Detect known suspicious behavior.

## Phase 3 — Correlation

Build:

- identity correlation;
- session correlation;
- source correlation;
- temporal sequence analysis.

Goal:

> Detect attack chains.

## Phase 4 — Containment

Build:

- session revocation;
- account disable;
- source blocking;
- token revocation;
- service restriction.

Goal:

> Reduce attacker persistence and blast radius.

## Phase 5 — Distributed Enforcement

Build:

- local policy cache;
- signed commands;
- replay protection;
- emergency response.

Goal:

> Make containment fast and resilient.

## Phase 6 — Behavioral Intelligence

Build:

- statistical baselines;
- adaptive thresholds;
- anomaly scores;
- sequence models;
- optional ML;
- optional LLM reasoning for ambiguous incidents.

Goal:

> Detect behavior that was not previously encoded as a simple rule.

The LLM remains **OFF by default**. Enabling it is an explicit deployment/configuration decision.

---

# 37. Why ML Should Come Later

Machine learning is not the first problem to solve. The same principle applies even more strongly to an LLM: **the platform must remain secure and useful when no model is available**.

Without reliable telemetry, an ML/LLM system receives poor data.

Without context, anomalies become noisy.

Without deterministic policy, AI-generated recommendations are difficult to validate.

Without containment mechanisms, detection does not produce action.

The correct sequence is:

```text
Reliable telemetry
      ↓
Good event model
      ↓
Context
      ↓
Correlation
      ↓
Deterministic rules
      ↓
Behavioral models
      ↓
Optional ML / LLM reasoning
```

The objective is to build a security system that is understandable, deterministic, and operationally useful before it becomes sophisticated.

---

# 38. Detection Example: Credential Abuse

```text
09:00  failed login × 15
09:01  successful login
09:01  new session
09:02  privilege change
09:03  unusual API access
```

Possible detection output:

```text
Incident: Credential Abuse Suspected
Application: Application A
Identity: user_123
Evidence:
    - login burst
    - successful login after failures
    - new privilege
    - unusual resource access
```

Possible response:

```text
1. Revoke session
2. Disable identity
3. Notify administrator
4. Increase monitoring
5. Preserve evidence
```

---

# 39. Detection Example: Resource Enumeration

A single request:

```text
GET /patients/123
```

may be normal.

The sequence:

```text
GET /patients/1
GET /patients/2
GET /patients/3
...
GET /patients/50000
```

is much more informative.

The system can detect:

- sequential resource IDs;
- unusually high unique-resource count;
- unusually high access frequency;
- mismatch with normal user behavior.

Response options can include:

- increase monitoring;
- restrict the session;
- revoke the identity;
- notify the administrator.

---

# 40. Cross-Application Attack Example

Suppose an identity is compromised.

```text
Application A
    │
    └── unusual login

Application B
    │
    └── successful token use

Application C
    │
    └── mass data access
```

The central security plane sees:

```text
Identity X
    │
    ├── App A
    ├── App B
    └── App C
```

This can turn three independent logs into one correlated incident.

---

# 41. Security Platform Topology

The long-term topology may look like:

```text
                         PRIVATE SECURITY NETWORK

              ┌────────────────────────────────────┐
              │     Security Control Plane         │
              │                                    │
              │  Ingestion                         │
              │  Correlation                       │
              │  Detection                         │
              │  Policy                            │
              │  Incidents                         │
              │  Alerting                          │
              │  Security Database                 │
              └─────────────────┬──────────────────┘
                                │
                         secure control channel
                                │
               ┌────────────────┼────────────────┐
               │                │                │
               ▼                ▼                ▼
          Agent A           Agent B           Agent C
               │                │                │
               ▼                ▼                ▼
            App A            App B            App C
```

The **security control plane itself should be private** and should not require a public Internet interface for ordinary administration.

---

# 42. Fast-Path vs Slow-Path Architecture

This is a central systems concept.

```text
                         REQUEST
                            │
                            ▼
                     ┌─────────────┐
                     │ Application │
                     └──────┬──────┘
                            │
                 ┌──────────┴──────────┐
                 │                     │
                 ▼                     ▼
             FAST PATH              SLOW PATH
                 │                     │
                 │                     ├── ingestion
                 │                     ├── correlation
                 │                     ├── detection
                 │                     ├── risk analysis
                 │                     ├── incident creation
                 │                     └── alerting
                 │
                 ▼
              RESPONSE
```

The fast path must remain simple.

The slow path can be computationally expensive.

---

# 43. Potential Low-Latency Technologies

The design should remain technology-neutral, but latency-sensitive implementations can evaluate:

- Rust;
- C++;
- Go;
- asynchronous I/O;
- Unix domain sockets;
- lock-free or low-contention queues;
- memory-resident policy maps;
- CPU affinity;
- NUMA-aware allocation;
- efficient binary event encodings;
- high-quality NICs;
- XDP/eBPF for selected packet-level controls.

These should only be introduced where measurements justify the complexity.

---

# 44. eBPF / XDP as an Optional Future Layer

For selected low-level network controls:

```text
NIC
 │
 ▼
XDP / eBPF
 │
 ├── obvious blocked source
 ├── connection flood
 └── basic packet filtering
 │
 ▼
Application / Agent
```

The purpose is not to place the entire detection engine inside eBPF.

The purpose is to cheaply discard or classify traffic at a lower level when there is a clear performance benefit.

---

# 45. Benchmarking Strategy

The platform should be built together with a benchmarking harness.

Measure:

```text
Requests/sec
p50 latency
p95 latency
p99 latency
p99.9 latency
CPU overhead
Memory overhead
Event throughput
Queue depth
Telemetry loss
Detection latency
Containment latency
```

Test at:

```text
Normal traffic
High traffic
Burst traffic
High concurrency
Controller unavailable
Storage unavailable
Detection engine degraded
Application under CPU pressure
```

The engineering objective is not to claim:

> "The gateway is fast."

It is to prove:

> "The security telemetry mechanism contributes X µs of overhead at p99 under a measured workload."

---

# 46. Security of the Control Plane

The security platform is itself a high-value target.

Its compromise could affect many protected systems.

Controls should include:

- strong agent identity;
- mutual authentication;
- encrypted communication;
- least privilege;
- signed policy versions;
- signed response commands;
- isolated administrative access;
- immutable or protected audit logs;
- privileged action approval where required;
- strict secret management;
- continuous health monitoring.

---

# 47. Control Plane as a High-Trust System

The trust relationships should be explicit.

```text
                    TRUST BOUNDARY

             ┌───────────────────────┐
             │ Security Controller   │
             └───────────┬───────────┘
                         │
               authenticated channel
                         │
             ┌───────────┴───────────┐
             │                       │
             ▼                       ▼
         Security Agent         Security Agent
             │                       │
             ▼                       ▼
         Application             Application
```

An application should not automatically have unrestricted authority over the central controller.

An agent should receive only the minimum privileges required to execute its allowed local actions.

---

# 48. Incident Evidence Model

An incident should retain enough evidence to answer:

- What happened?
- When did it happen?
- Which application was affected?
- Which identity was involved?
- Which source was involved?
- Which resources were accessed?
- What evidence triggered the decision?
- What policy was active?
- What response occurred?
- Who or what authorized the response?
- What was the outcome?

Example:

```text
Incident 1042
│
├── Evidence
│   ├── failed logins
│   ├── session creation
│   ├── privilege change
│   └── mass export
│
├── Decision
│   └── credential compromise suspected
│
├── Response
│   ├── revoke session
│   └── disable identity
│
└── Outcome
    └── suspicious activity stopped
```

---

# 49. Administrative UI

The dashboard should focus on **security state and relationships**, not merely raw logs.

Useful views include:

```text
Overview
   ├── Active incidents
   ├── Threats detected
   ├── Applications
   ├── Agents
   └── System health

Applications
   ├── traffic profile
   ├── anomalies
   ├── active incidents
   └── agent status

Identity
   ├── sessions
   ├── risk history
   ├── anomalies
   └── containment actions

Incidents
   ├── timeline
   ├── evidence
   ├── decisions
   └── response history
```

---

# 50. Observability of the Security System

The security platform must monitor itself.

Key metrics:

```text
Event ingestion rate
Event processing rate
Queue depth
Dropped events
Detection latency
Correlation latency
Containment latency
Agent connectivity
Controller availability
Policy synchronization state
Command failures
Storage utilization
```

If the platform cannot establish whether it is healthy, it cannot be trusted as a security control plane.

---

# 51. Threat Model

The platform should explicitly model at least:

```text
External attacker
Compromised account
Compromised application
Compromised host/container
Malicious insider
Credential theft
Token theft
Privilege escalation
Resource enumeration
Mass data access
Lateral movement
Abuse of administrative operations
Security controller compromise
Agent compromise
Telemetry tampering
```

The goal is not to solve every threat synchronously.

The goal is to detect meaningful evidence and reduce damage when a threat develops.

---

# 52. Attack Containment Philosophy

The preferred progression is:

```text
Observe
   ↓
Increase confidence
   ↓
Restrict
   ↓
Contain
   ↓
Isolate
   ↓
Recover
```

The system should avoid destructive actions based solely on weak signals unless a policy explicitly permits them.

---

# 53. Blast Radius Reduction

One of the most important benefits of the architecture is **blast-radius reduction**.

Without centralized containment:

```text
Compromised Identity
       │
       ├── App A
       ├── App B
       ├── App C
       └── Database
```

With centralized correlation:

```text
Compromised Identity
       │
       ▼
Security Controller
       │
       ├── revoke App A session
       ├── revoke App B session
       ├── revoke App C session
       ├── block credential
       └── alert administrator
```

The security plane becomes a **containment coordinator**.

---

# 54. What the Platform Does Not Replace

This platform should complement, not eliminate:

- application authentication;
- authorization;
- secure coding practices;
- database access controls;
- network firewalls;
- TLS;
- secret management;
- patch management;
- backups;
- application-level validation.

Out-of-band security is not an excuse to remove the application's own controls.

Instead:

```text
Application security
        +
Infrastructure security
        +
Central detection
        +
Central containment
        =
Layered defense
```

---

# 55. Example End-to-End Incident

```text
1. Attacker obtains an application credential.

2. Login burst appears.

3. Successful login occurs.

4. New session is created.

5. Session accesses a privileged endpoint.

6. Privilege changes.

7. Large number of records are read.

8. Export starts.

9. Application continues responding normally.

10. Security Agent emits events asynchronously.

11. Security Plane correlates events.

12. Risk exceeds containment threshold.

13. Incident is created.

14. Response policy selects session revocation.

15. Local Agent revokes the session.

16. Administrator receives alert.

17. Evidence remains available for investigation.
```

This is the intended operating model.

---

# 56. Reference Technology Options

Technology should be selected according to actual requirements and measured bottlenecks. The project should deliberately study mature open-source security systems rather than reimplementing their ideas blindly. Three projects are especially important to the architecture: **Cilium Tetragon, Falco, and Cilium**. They are complementary rather than interchangeable.

## 56.1 Open-Source Systems to Study

### Tetragon — Runtime Security and Enforcement

**Project:** Cilium Tetragon

Tetragon is an eBPF-based runtime security and observability system focused on observing and enforcing security-relevant activity at the kernel/runtime boundary. It is highly relevant to this project because it demonstrates how process, system-call, file, and network activity can be observed without inserting an application-layer proxy into every request path.

Study Tetragon for:

- eBPF-based event collection;
- kernel/runtime visibility;
- process and network event models;
- low-overhead telemetry;
- runtime policy enforcement;
- event filtering;
- container-aware security;
- practical enforcement boundaries.

Repository: https://github.com/cilium/tetragon

### Falco — Behavioral Runtime Detection

**Project:** Falco

Falco is an open-source runtime security project centered on detecting suspicious system and container behavior from event streams and rules. It is especially useful for understanding the deterministic detection side of the proposed control plane.

Study Falco for:

- event-driven detection;
- rule-based behavioral analysis;
- system-call and container telemetry;
- suspicious sequence detection;
- alert semantics;
- reducing noisy low-level events into meaningful security signals.

Repository: https://github.com/falcosecurity/falco

### Cilium — Identity-Aware Networking and Policy

**Project:** Cilium

Cilium uses eBPF to provide networking, observability, identity-aware policy, and security capabilities, particularly in containerized and Kubernetes environments. It is valuable for understanding how security policy can operate at infrastructure boundaries while still preserving performance.

Study Cilium for:

- eBPF networking;
- service identity;
- network policy;
- service-to-service visibility;
- flow observability;
- policy enforcement;
- Kubernetes-aware security architecture.

Repository: https://github.com/cilium/cilium

### How the Three Projects Fit the Proposed Platform

These projects should be treated as **reference implementations and potential integrations**, not as three competing replacements for the platform.

```text
                Protected Applications
                         |
             +-----------+-----------+
             |           |           |
             v           v           v
          Tetragon     Falco      Cilium
             |           |           |
             +-----------+-----------+
                         |
                         v
                Event Normalization
                         |
                         v
                Correlation Engine
                         |
                         v
                Policy / Detection
                         |
                         v
                Response Controller
```

A practical implementation may initially integrate one source at a time. The architecture should keep the event model independent of the source so that Tetragon, Falco, Cilium, application agents, and future sources can all feed the same security pipeline.

## 56.2 Other Relevant Open-Source Systems

Additional systems are useful as reference points:

- **Zeek** for network behavioral analysis;
- **Suricata** for network IDS/IPS concepts;
- **OpenTelemetry** for standardized telemetry and distributed context;
- **Wazuh** for security monitoring and correlation concepts;
- **OpenSearch Security / Elastic Security** for event search, dashboards, and security analytics;
- **Nuclei / OWASP ZAP** for offensive validation and application security testing.

The objective is not to duplicate these systems. The objective is to understand their observability boundaries, event models, detection methods, performance tradeoffs, and response mechanisms.

## 56.3 Strix — Optional Offensive Validation Integration

**Project:** Strix

Strix is an autonomous AI penetration-testing platform. It is not the runtime security control plane described by this document, but it is potentially useful as an **offensive validation component**.

A future workflow could use Strix to validate whether an observed weakness or suspicious behavior corresponds to an exploitable application-level condition. This should be treated as an investigation/validation capability, not as a trusted runtime decision-maker.

Repository: https://github.com/usestrix/strix

## Edge / Existing Traffic Infrastructure

Possible options:

- existing reverse proxy;
- load balancer;
- Envoy;
- HAProxy;
- NGINX;
- cloud-native network controls.

The architecture does **not** require replacing existing edge infrastructure.

## Agent

Possible implementations:

- language SDK;
- sidecar;
- local daemon;
- Unix-socket collector.

## Event Pipeline

Possible technologies:

- local queues;
- Kafka-compatible streams;
- NATS;
- Redis Streams;
- custom event transport.

The chosen technology should follow volume and reliability requirements rather than novelty.

## Storage

Possible technologies:

- PostgreSQL;
- ClickHouse;
- OpenSearch;
- object storage;
- specialized event stores.

A hybrid architecture may be appropriate.

## LLM / AI Reasoning Layer (Optional)

The security platform should support two operating modes. **Deterministic mode is the default and must be fully functional without an LLM.** AI is an optional expansion for ambiguous incidents, higher-order reasoning, investigation assistance, and analyst workflow.

### Mode A — Deterministic / LLM OFF

```text
Event
  ↓
Policy Engine
  ↓
+-----------+-----------+
|                       |
Allowed               Matched threat
|                       |
Pass                  Response
```

Properties:

- no LLM dependency;
- deterministic decisions;
- predictable performance;
- suitable for disconnected/private environments;
- easier auditing and testing;
- lower infrastructure cost;
- security continues to operate when AI services are unavailable.

This is the **baseline security mode** and should be enabled by default.

### Mode B — Intelligent / LLM ON

The LLM should be invoked only when deterministic rules classify an event or incident as unknown, ambiguous, or requiring deeper contextual reasoning.

```text
Event
  ↓
Policy Engine
  ↓
Known? ───────────── YES ──────► Deterministic Response
  │
  NO / UNCERTAIN
  │
  ▼
Context Builder
  │
  ▼
LLM Reasoning Layer
  │
  ▼
Structured Recommendation
  │
  ▼
Response Validator
  │
  ▼
Policy Authorization
  │
  ▼
Response Controller
```

The LLM should receive **security context**, not unrestricted access to the production environment. Context can include:

- normalized events;
- recent event sequences;
- affected application;
- actor/session information;
- applicable policies;
- resource classifications;
- historical incident context;
- evidence selected by deterministic systems.

The LLM should return a constrained, machine-readable recommendation such as:

```json
{
  "classification": "SUSPICIOUS",
  "confidence": 0.91,
  "reason_codes": [
    "UNUSUAL_PROCESS",
    "UNUSUAL_NETWORK_CONNECTION"
  ],
  "recommended_action": "ISOLATE_SERVICE"
}
```

The LLM must **not** directly execute arbitrary shell commands or unrestricted infrastructure actions. Any recommended response must pass through deterministic validation and policy authorization before enforcement.

### LLM Provider Independence

The platform should keep the reasoning interface provider-neutral so that the optional model can be:

- disabled completely;
- a local model;
- a private model server;
- a cloud-hosted model;
- replaced without changing the core security engine.

The security control plane must not become dependent on a particular model vendor.

### Cost and Latency Policy

LLM calls must remain **off the normal request path** and should normally be asynchronous. The system should avoid sending every event to a model. A policy/routing layer should decide when an event warrants deeper reasoning.

```text
10,000,000 events
        ↓
Deterministic filtering
        ↓
Suspicious / uncertain subset
        ↓
Context aggregation
        ↓
Optional LLM analysis
```

The platform should record:

- model invocation rate;
- model latency;
- cost where applicable;
- recommendation confidence;
- validation outcomes;
- false-positive/false-negative feedback.

### LLM Safety Principle

The LLM is a **reasoning assistant**, not the security root of trust.

```text
Telemetry → Rules → Context → LLM → Recommendation
                                      ↓
                              Deterministic Validator
                                      ↓
                                Policy Engine
                                      ↓
                                Enforcement
```

This guarantees that turning the LLM off does not disable the core security controls.

---

# 57. Recommended Initial Architecture

For an initial implementation, keep it intentionally simple:

```text
                     ┌───────────────────────┐
                     │ Security Controller   │
                     │                       │
                     │ FastAPI / Go / Rust   │
                     │                       │
                     │ Ingestion             │
                     │ Rule Engine            │
                     │ Incident Engine        │
                     └───────────┬───────────┘
                                 │
                           secure channel
                                 │
              ┌──────────────────┼──────────────────┐
              │                  │                  │
              ▼                  ▼                  ▼
          Agent A             Agent B             Agent C
              │                  │                  │
              ▼                  ▼                  ▼
            App A              App B              App C
```

Start with structured events and deterministic detection.

Then add:

```text
Correlation
   ↓
Behavioral baselines
   ↓
Automated containment
   ↓
Advanced analytics
   ↓
Optional ML
```

---

# 58. Engineering Principles

The project should maintain the following principles.

### Principle 1 — Security should be observable

Unknown behavior is difficult to protect.

### Principle 2 — The hot path should be boring

The synchronous request path should perform as little security work as possible.

### Principle 3 — Intelligence belongs off-path

Expensive correlation and analysis belong in the control plane.

### Principle 4 — Enforcement should be local when possible

Local agents can execute containment faster than repeated central round trips.

### Principle 5 — The controller should not become an outage trigger

Security infrastructure must not unnecessarily become a mandatory availability dependency.

### Principle 6 — Evidence matters

Every major security decision should be explainable.

### Principle 7 — Measure everything

Performance and detection quality must be measured rather than assumed.

---

# 59. Final Target Architecture

```text
                               INTERNET
                                  │
                                  ▼
                      ┌──────────────────────┐
                      │ Existing Network Edge│
                      │ Firewall / LB / Proxy│
                      └───────────┬──────────┘
                                  │
                  ┌───────────────┼────────────────┐
                  │               │                │
                  ▼               ▼                ▼
             Application A   Application B   Application C
                  │               │                │
                  ▼               ▼                ▼
               Agent A         Agent B          Agent C
                  │               │                │
                  └───────────────┼────────────────┘
                                  │
                           ASYNC TELEMETRY
                                  │
                                  ▼
                    ┌─────────────────────────┐
                    │   INGESTION PIPELINE    │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │ NORMALIZATION / ENRICH  │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │ CORRELATION ENGINE      │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │ DETECTION ENGINE        │
                    │ Rules + Behavior + ML   │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │ RISK / POLICY ENGINE    │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │ INCIDENT / RESPONSE     │
                    └───────┬─────────┬───────┘
                            │         │
                            ▼         ▼
                         ALERTS   CONTROL COMMANDS
                                      │
                         ┌────────────┼────────────┐
                         ▼            ▼            ▼
                      Agent A      Agent B      Agent C
                         │            │            │
                         ▼            ▼            ▼
                     CONTAIN       CONTAIN      CONTAIN
```

---

# 60. Final Design Principle

The entire system can be reduced to one engineering proposition:

> **Keep normal application traffic fast and independent. Continuously emit security telemetry without blocking the request. Move expensive intelligence into a private control plane. Correlate behavior across applications. When the evidence becomes strong enough, use a secure control channel to rapidly contain the affected identity, session, service, or application.**

The resulting architecture is not simply a reverse proxy, WAF, logging system, or SIEM.

It is a **distributed security control and containment platform** with:

```text
Telemetry
   ↓
Context
   ↓
Correlation
   ↓
Detection
   ↓
Decision
   ↓
Containment
   ↓
Evidence
   ↓
Recovery
   ↓
Learning
```

That chain is the foundation of the project.

---

# Appendix A — Conceptual Component Map

```text
security-platform/
│
├── agent/
│   ├── collector
│   ├── normalizer
│   ├── local_queue
│   ├── policy_cache
│   └── enforcement
│
├── control-plane/
│   ├── ingestion
│   ├── correlation
│   ├── detection
│   ├── policy
│   ├── risk
│   ├── incident
│   ├── response
│   └── alerting
│
├── storage/
│   ├── events
│   ├── incidents
│   ├── policies
│   └── audit
│
├── admin-ui/
│   ├── overview
│   ├── incidents
│   ├── applications
│   ├── identities
│   └── policies
│
└── benchmarks/
    ├── latency
    ├── throughput
    ├── event-loss
    └── containment
```

---

# Appendix B — Conceptual Request / Event Timeline

```text
TIME ──────────────────────────────────────────────────────────────►

Client        Application              Agent           Security Plane
  │                │                    │                    │
  │ Request        │                    │                    │
  ├───────────────►│                    │                    │
  │                │ Process            │                    │
  │                ├───────────────────►│ Event              │
  │                │                    │ Queue              │
  │◄───────────────┤ Response            │                    │
  │                │                    ├───────────────────►│
  │                │                    │                    │ Detect
  │                │                    │                    │ Correlate
  │                │                    │                    │ Decide
  │                │                    │◄───────────────────┤ Command
  │                │◄───────────────────┤                    │
  │                │ Local containment   │                    │
```

---

# Appendix C — Key Questions for Future Design Reviews

Before implementation, the team should explicitly answer:

1. What telemetry is collected from each application?
2. What is the maximum acceptable synchronous overhead?
3. What events must be durably queued?
4. What is the event-loss policy under overload?
5. Which actions can the local agent execute without the controller?
6. Which containment actions require human approval?
7. How are agents authenticated?
8. How are response commands authenticated and protected against replay?
9. What data is prohibited from entering the security store?
10. How is application identity correlated across systems?
11. What is the retention period for raw telemetry?
12. How are policies versioned and rolled back?
13. How is the control plane itself isolated and monitored?
14. What benchmark defines acceptable latency overhead?
15. What conditions trigger automatic isolation?

---

# Appendix D — One-Sentence Project Definition

> **A private, distributed security control plane that asynchronously observes multiple applications, correlates their behavior, detects abnormal activity, and rapidly orchestrates containment without making centralized security analysis a synchronous dependency of normal application traffic.**
