# Distributed Security Control Plane — Architecture Overview

An open-source security control-plane architecture for distributed applications. It separates application execution from security observation, detection, correlation, incident management, and containment.

## Core Principle
> Security should observe and control applications without becoming a dependency of their normal request path.

## Data Plane vs Security Control Plane
```text
CLIENT
  │
  ▼
APPLICATION / SERVICE
  │
  ├──────────────► NORMAL RESPONSE
  │
  └── asynchronous telemetry ──► SECURITY CONTROL PLANE
                                      │
                                      ▼
                              IDENTITY RESOLUTION
                                      │
                                      ▼
                              DETECTION & CORRELATION
                                      │
                                      ▼
                                RISK & POLICY
                                      │
                                      ▼
                              INCIDENT MANAGEMENT
                                      │
                                      ▼
                              SIGNED CONTAINMENT
                                      │
                                      ▼
                                  LOCAL AGENT
```

## Telemetry
The control plane is designed to combine application, runtime/kernel, and network security signals. Application telemetry can provide user, session, authentication, request, and application-action context. Runtime and kernel telemetry can provide process, syscall, container, and behavioral signals. Network telemetry can provide connection, flow, service-to-service, and protocol context.

Target integrations include eBPF-based tooling such as Cilium Tetragon, Falco, and Cilium Hubble.

## Canonical Event Model
Different sensors expose different schemas. A canonical event model allows heterogeneous telemetry sources to participate in common security processing while preserving source-specific metadata.

```text
Sensor → Raw Event → Validation / Normalization → Canonical Security Event
```

## Identity Resolution and Correlation
Events may identify the same activity through different dimensions such as user, session, IP, application, container, and process. Identity resolution connects these dimensions so the correlation engine can recognize activity that crosses service boundaries.

```text
User → Session → IP / Network Identity → Application → Container → Process
```

## Deterministic Detection
The core detection model is deterministic and reproducible. Representative patterns include credential brute force, rapid API enumeration, repeated unauthorized request bursts, suspicious runtime behavior, container shell execution, and multi-stage cross-application sequences.

## Risk, Policy, and Incidents
Security reasoning is separated into stages:

```text
Evidence → Detection → Risk → Policy → Incident / Action
```

This separation allows detection logic and response policy to evolve independently.

## Containment
Containment is coordinated by the control plane and enforced close to the protected workload. Planned capability classes include REVOKE_SESSION, THROTTLE_ACTOR, BLOCK_NETWORK, and ISOLATE_SERVICE.

```text
CONTROL PLANE
     │
     │ Ed25519 signed command + TTL
     ▼
 LOCAL AGENT
     │
     ▼
 ENFORCEMENT
```

## State Architecture
Redis is intended for hot operational state such as sliding windows, short-lived context, blacklists, and pub/sub. PostgreSQL is intended for durable state such as incidents, audit records, selected events, and historical decisions.

## Advisory AI
The optional AI layer is outside the security root of trust. It can provide advisory reasoning for ambiguous incidents but has no direct execution authority. Deterministic policy and enforcement remain responsible for binding security actions.

## Resilience
A core objective is graceful degradation. Failure of the security controller should not automatically make the normal application request path unavailable. Deployment-specific buffering and local policy state can allow observation or enforcement to continue during controller failures.

## Technology
- Rust / Tokio / Axum
- Redis
- PostgreSQL
- React / TypeScript / Vite
- Python
- WebSockets
- eBPF / Cilium Tetragon / Falco / Hubble
- Prometheus / Grafana

## Scope and Discovery Keywords
This project covers distributed security control planes, asynchronous security telemetry, application security telemetry, runtime security, eBPF observability, identity resolution, cross-application threat correlation, deterministic threat detection, incident response, security policy, cryptographically authenticated containment, security automation, and out-of-band security architecture.

See the [main README](../README.md) for current implementation status and roadmap.