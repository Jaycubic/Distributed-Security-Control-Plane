# Distributed Security Control Plane

The Distributed Security Control Plane is an asynchronous, out-of-band security architecture designed to provide security telemetry collection, cross-application correlation, deterministic threat detection, incident management, and automated containment without placing security processing on the critical request path of protected applications.

The core architectural principle is simple:

> **Security should observe and control applications without becoming a dependency of their normal request path.**

Applications continue serving normal traffic independently while security telemetry is processed by a separate control plane.

---

## 1. Architectural Overview

The system separates normal application execution from security processing.

```text
                    DATA PLANE
                        
        ┌──────────────────────────────┐
        │        Applications          │
        │                              │
        │  FastAPI / Node.js / Others  │
        └──────────────┬───────────────┘
                       │
                       │ Asynchronous Telemetry
                       ▼

                 SECURITY PLANE

        ┌──────────────────────────────┐
        │       Telemetry Layer        │
        │                              │
        │ Application / Runtime /      │
        │ Network Security Signals     │
        └──────────────┬───────────────┘
                       │
                       ▼
        ┌──────────────────────────────┐
        │       Event Ingestion        │
        └──────────────┬───────────────┘
                       │
                       ▼
        ┌──────────────────────────────┐
        │     Identity Resolution      │
        │                              │
        │ IP / Session / User / PID /  │
        │ Container / Application     │
        └──────────────┬───────────────┘
                       │
                       ▼
        ┌──────────────────────────────┐
        │ Detection & Correlation      │
        │                              │
        │ Rules / Sliding Windows /    │
        │ Attack-Chain Correlation     │
        └──────────────┬───────────────┘
                       │
                       ▼
        ┌──────────────────────────────┐
        │       Risk & Policy          │
        └──────────────┬───────────────┘
                       │
                       ▼
        ┌──────────────────────────────┐
        │     Incident Management      │
        └──────────────┬───────────────┘
                       │
                       ▼
        ┌──────────────────────────────┐
        │       Containment            │
        │                              │
        │ Session Revocation /         │
        │ Throttling / Network Block / │
        │ Service Isolation            │
        └──────────────┬───────────────┘
                       │
                       │ Signed Command
                       ▼
                 LOCAL AGENT
```

---

## 2. Data Plane and Security Control Plane

### Data Plane

The data plane consists of the applications and services handling normal user and system traffic.

Its primary responsibility is application functionality.

Security processing is intentionally kept off the critical request path.

A normal request should conceptually behave like:

```text
Client
  │
  ▼
Application
  │
  ▼
Response
```

The application does not need to wait for:

- Security event ingestion
- Event correlation
- Detection processing
- Risk calculation
- Incident creation
- AI analysis
- Security controller decisions

### Security Control Plane

The security control plane operates independently from normal application execution.

It receives telemetry, builds security context, detects suspicious behavior, correlates activity across applications, manages incidents, and can issue containment commands.

Conceptually:

```text
Application
     │
     │ asynchronous telemetry
     ▼
Security Control Plane
```

The security plane therefore observes the data plane rather than becoming part of its normal execution path.

---

## 3. Why Out-of-Band Security?

Traditional security architectures frequently place security enforcement directly between a client and application.

```text
Client
  │
  ▼
Security Layer
  │
  ▼
Application
  │
  ▼
Response
```

This can make the security component a dependency of application availability and request latency.

The Distributed Security Control Plane instead uses an asynchronous architecture:

```text
Client ───────────────► Application ─────────► Response
                           │
                           │
                           │ asynchronous
                           ▼
                    Security Control Plane
```

This provides a separation between:

1. Application availability
2. Security observation
3. Security analysis
4. Security response

The objective is not to eliminate security enforcement, but to move security intelligence and coordination away from the application's critical request path.

---

## 4. Telemetry

The control plane can consume security signals from multiple layers.

### Application Layer

Application telemetry can provide context such as:

- User identity
- Session information
- API requests
- Authentication activity
- Application actions
- Application-specific security events

### Runtime Layer

Runtime security telemetry can provide information about:

- Process execution
- Container activity
- Kernel-level behavior
- Suspicious process creation
- Shell execution
- Runtime security events

Technologies such as eBPF-based security tooling can provide visibility at this layer.

### Network Layer

Network telemetry can provide:

- Network connections
- Network flows
- Service-to-service communication
- Source and destination information
- Additional protocol context

The purpose of combining these layers is to create security context that cannot be obtained reliably from a single telemetry source.

---

## 5. Canonical Event Model

Different security sensors produce different event formats.

The control plane therefore requires a normalized representation of security events.

Conceptually:

```text
Sensor
  │
  ▼
Raw Event
  │
  ▼
Canonical Event
  │
  ▼
Security Processing
```

A canonical event can contain information such as:

- Event type
- Timestamp
- Source
- Actor
- User
- Session
- Application
- Process
- Container
- Network information
- Event metadata

Normalization allows different telemetry sources to participate in the same detection and correlation pipeline.

---

## 6. Identity Resolution

Security events rarely contain a single universal identity.

The same activity may appear through multiple identifiers:

```text
User
 │
 └── Session
       │
       └── IP Address
              │
              └── Application
                     │
                     └── Container
                            │
                            └── Process
```

The control plane can resolve relationships between these identifiers to construct a broader security context.

Relevant identifiers may include:

- IP address
- User ID
- Session ID
- Process ID
- Container ID
- Application identity

This allows events that initially appear unrelated to be associated with the same actor, session, workload, or attack chain.

---

## 7. Cross-Application Correlation

A major purpose of the control plane is to detect behavior that crosses application boundaries.

For example:

```text
Application A
      │
      └── Suspicious authentication activity
                │
                ▼
Application B
      │
      └── API enumeration
                │
                ▼
Application C
      │
      └── Sensitive data access
```

Each event may have limited significance when viewed independently.

Correlation allows the control plane to construct a broader sequence:

```text
Reconnaissance
      │
      ▼
Credential Activity
      │
      ▼
Lateral Movement
      │
      ▼
Resource Access
      │
      ▼
Potential Exfiltration
```

The control plane therefore focuses not only on individual events but also on relationships and sequences of events.

---

## 8. Deterministic Detection

The primary detection layer is deterministic.

Examples of detection patterns include:

- Credential brute force
- Rapid API enumeration
- Unauthorized request bursts
- Suspicious runtime behavior
- Container shell execution
- Repeated security signals within a defined time window

A simplified detection pipeline is:

```text
Event
  │
  ▼
Sliding Window
  │
  ▼
Signal Accumulation
  │
  ▼
Rule Evaluation
  │
  ▼
Detection
  │
  ▼
Risk / Incident
```

Deterministic rules provide predictable and reproducible security decisions.

---

## 9. Risk and Policy

Detection, risk, and policy represent different stages of security reasoning.

### Detection

Determines whether observed activity matches a known suspicious pattern.

### Risk

Represents the significance of accumulated evidence and context.

### Policy

Determines what action is permitted when a security condition is reached.

Conceptually:

```text
Evidence
   │
   ▼
Detection
   │
   ▼
Risk
   │
   ▼
Policy
   │
   ▼
Action
```

This separation allows detection logic and response policy to evolve independently.

---

## 10. Incident Lifecycle

Detected security activity can be represented as an incident rather than treated as an isolated event.

A simplified lifecycle is:

```text
Telemetry
   │
   ▼
Detection
   │
   ▼
Incident Created
   │
   ▼
Investigation
   │
   ▼
Containment
   │
   ▼
Recovery
   │
   ▼
Resolution
```

Incident records provide a persistent representation of security activity and response decisions.

---

## 11. Containment

The control plane is designed not only to detect suspicious activity but also to coordinate containment.

Possible containment actions include:

```text
REVOKE_SESSION
THROTTLE_ACTOR
BLOCK_NETWORK
ISOLATE_SERVICE
```

Containment commands are intended to be delivered to local enforcement agents.

Conceptually:

```text
Security Control Plane
          │
          │ Signed Command
          │ + TTL
          ▼
      Local Agent
          │
          ▼
      Enforcement
```

The local agent provides an enforcement boundary close to the protected application or workload.

---

## 12. Cryptographic Command Trust

Security control commands are security-sensitive operations.

Commands can therefore be cryptographically signed using Ed25519.

```text
Control Plane
      │
      │ Private Key
      ▼
Signed Command
      │
      ▼
Local Agent
      │
      │ Public Key Verification
      ▼
Command Accepted
      │
      ▼
Enforcement
```

Commands also have a mandatory time-to-live (TTL).

The combination of:

- Cryptographic authentication
- Command integrity
- Explicit expiration

provides a mechanism for preventing unauthorized or indefinitely valid control commands.

---

## 13. State Architecture

The system uses different storage layers for different classes of security state.

### Redis

Redis is intended for hot, rapidly changing state such as:

- Sliding windows
- Active security context
- Temporary state
- Pub/Sub communication
- Short-lived enforcement information

Conceptually:

> Redis answers: **"What is happening now?"**

### PostgreSQL

PostgreSQL provides persistent state such as:

- Incidents
- Audit records
- Historical information
- Security decisions
- Persistent application data

Conceptually:

> PostgreSQL answers: **"What happened, and what did we record?"**

This separation allows high-frequency security state and durable historical state to be handled differently.

---

## 14. Advisory AI

The architecture includes an optional AI/LLM layer.

AI is intentionally separated from deterministic security enforcement.

```text
Security Engine
      │
      │ Incident Context
      ▼
  AI Advisor
      │
      │ Recommendation
      ▼
Security System
```

The AI component is advisory.

It does not receive direct authority to execute containment actions.

The security architecture therefore maintains a separation between:

```text
AI Reasoning
     ≠
Security Authority
```

Deterministic security logic and policy remain responsible for security decisions and enforcement.

The AI service can be disabled independently without making it a dependency of the normal security pipeline.

---

## 15. Failure and Resilience

An important architectural property is graceful degradation.

The application should not become dependent on the availability of the entire security control plane for normal request processing.

For example:

```text
Security Control Plane
        │
        X unavailable
        │
        ▼

Application
        │
        ▼
Normal traffic continues
```

Depending on the component and failure mode, telemetry may be buffered or temporarily unavailable while local enforcement can continue using previously available security state or policies.

This architecture treats security processing and application availability as related but separately managed concerns.

---

## 16. Threat Model

The security architecture considers several trust boundaries and attack surfaces.

Potential assets include:

- Application availability
- User sessions
- Security telemetry
- Incident records
- Security policies
- Cryptographic keys
- Containment commands

Potential attack surfaces include:

- Applications
- Telemetry interfaces
- Local agents
- Event transport
- Redis
- PostgreSQL
- Control channels
- Dashboard/API interfaces
- AI advisory services

The threat model should evolve alongside the implementation as additional telemetry sources, enforcement mechanisms, and distributed deployment capabilities are introduced.

---

## 17. Design Principles

The Distributed Security Control Plane is built around the following principles:

### 1. Out-of-band security

Security processing should not become a dependency of normal application requests.

### 2. Asynchronous telemetry

Applications should emit security telemetry without synchronously waiting for security processing.

### 3. Cross-layer visibility

Application, runtime, and network signals should be capable of contributing to the same security context.

### 4. Cross-application correlation

Security events should be correlated beyond individual application boundaries.

### 5. Deterministic enforcement

Security-critical decisions should remain predictable and policy-driven.

### 6. Cryptographically authenticated control

Security commands should be authenticated and integrity-protected.

### 7. Local enforcement

Containment commands should ultimately be enforceable close to the protected workload.

### 8. Graceful degradation

Failure of security processing should not automatically become failure of normal application traffic.

### 9. Advisory AI

AI may assist investigation and reasoning without receiving direct security execution authority.

---

## 18. Project Evolution

The architecture is being developed incrementally.

The planned evolution includes:

```text
Foundation
    │
    ▼
Detection
    │
    ▼
Identity & Correlation
    │
    ▼
Containment
    │
    ▼
Kernel / Runtime Telemetry
    │
    ▼
Advisory AI
    │
    ▼
Observability & Packaging
```

Each stage expands the control plane while preserving the core architectural principle of keeping security processing independent from the application's critical request path.

---

## 19. Further Documentation

The Wiki is organized around the major architectural domains of the system.

Suggested documentation pages:

- System Architecture
- Data Plane vs Control Plane
- Telemetry Architecture
- Canonical Event Model
- Identity Resolution
- Cross-Application Correlation
- Detection Engine
- Risk and Policy Engine
- Incident Lifecycle
- Containment Architecture
- Cryptographic Trust Model
- State Architecture
- Runtime Security
- Failure and Resilience
- Threat Model
- Advisory AI Architecture
- Performance and Benchmarks
- Development Roadmap
- Contributor Architecture Guide

---

## 20. Core Architectural Statement

The Distributed Security Control Plane is based on a simple separation:

```text
APPLICATION EXECUTION
        │
        │ must remain available
        ▼
     DATA PLANE


SECURITY OBSERVATION
        │
        ▼
SECURITY REASONING
        │
        ▼
SECURITY DECISION
        │
        ▼
SECURITY ENFORCEMENT

        │
        ▼
   CONTROL PLANE
```

The control plane exists to provide security intelligence and coordinated response without requiring applications to synchronously depend on the security system for every request.

That separation is the foundation of the architecture.
