# Changelog

## [Unreleased]

### Added
- Documented the deterministic sliding-window detection rules (`docs/DETECTION-RULES.md`): the six default engine rules with their exact thresholds, windows, and state keys, the risk-escalation ladder, and the hot-state primitive they run on, kept in lockstep with the implementation (`#2`).

All notable project changes are documented here.

## [0.3.0] — Identity, Correlation & Security Context

### Added
- Canonical security event model and asynchronous telemetry ingestion.
- Redis-backed hot operational state and in-memory sliding-window state.
- Deterministic detection rules and signal accumulation.
- Risk scoring and incident lifecycle management.
- Identity resolution across heterogeneous identifiers.
- Cross-application correlation and security context graph.
- Capability context inference.
- Operations dashboard and real-time event/incident streaming.
- Cross-application attack-chain simulation.
- Architecture documentation and software citation metadata.

### Security Architecture
- Maintains the out-of-band application/request-path invariant.
- Keeps advisory AI outside the security root of trust.
- Prepares the containment model around authenticated, time-bounded commands.

### Status
This is an active early-stage open-source engineering project. Interfaces and deployment assumptions may continue to evolve.

### Planned Next
- Graduated containment with signed commands and reversible TTLs.
- Kernel and runtime telemetry adapters.
- Optional off-path advisory LLM reasoning.
- Full observability, sustained benchmarking, fault-injection validation, and packaging.