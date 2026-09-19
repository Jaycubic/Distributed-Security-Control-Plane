# Detection and Correlation

The Distributed Security Control Plane combines deterministic detection with identity-aware correlation across heterogeneous security telemetry.

## Deterministic Detection

Deterministic rules are intended to produce predictable and reproducible security signals from observed evidence.

Representative detection classes in the current roadmap and implementation include:

- credential brute force
- rapid API enumeration
- repeated unauthorized request bursts
- suspicious runtime behavior
- container shell execution
- multi-stage cross-application attack sequences

## Sliding-Window Detection

Many behavioral detections depend on frequency within a time interval rather than one event in isolation.

```text
Events
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
Detection Signal
```

Redis is used for hot operational state in the architecture, while an in-memory implementation can support low-dependency local processing and testing.

## Identity Resolution

Security telemetry can expose different identifiers for the same underlying activity:

```text
User
  │
  └── Session
        │
        └── IP / Network Identity
              │
              └── Application
                    │
                    └── Container
                          │
                          └── Process
```

Identity resolution converts these heterogeneous identifiers into canonical security context.

## Cross-Application Correlation

Correlation extends detection beyond individual services.

```text
Reconnaissance
      ↓
Credential Activity
      ↓
Lateral Movement
      ↓
High-Impact Resource Access
      ↓
Potential Exfiltration
```

The purpose is not to assume that every sequence is malicious, but to accumulate related evidence and apply explicit detection and policy logic.

## Risk and Policy

Detection identifies a pattern. Risk represents the significance of accumulated evidence. Policy determines which response is permitted.

```text
Evidence → Detection → Risk → Policy → Action
```

Keeping these layers separate makes it possible to change policy without rewriting the underlying telemetry and detection model.

## Incident Synthesis

Detected signals can be grouped into persistent incidents so operators can inspect evidence, context, lifecycle state, and response decisions.

## Testing Correlation

Correlation logic should be tested against both expected attack sequences and difficult cases such as missing identifiers, incomplete telemetry, clock skew, TTL expiry, and events that should remain unrelated.