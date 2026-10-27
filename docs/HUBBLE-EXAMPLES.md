# Hubble telemetry: fixtures to canonical events

Cilium Hubble emits L3/L4/L7 flow logs describing network traffic between
workloads. The adapter in [`crates/sensors/src/hubble.rs`](../crates/sensors/src/hubble.rs)
normalizes each flow into the canonical [`SecurityEvent`](../crates/common/src/models.rs)
shape that detection, correlation, and advisory all read.

This page shows two representative raw fixtures (kept under
[`crates/sensors/fixtures/hubble/`](../crates/sensors/fixtures/hubble/)) — a `DROPPED` flow and an
`ALLOWED` flow — and maps each raw field to the canonical field the adapter fills, with
particular attention to how **service**, **endpoint**, **protocol**, and **flow context** are
resolved. The fixtures are the exact inputs the schema-preservation tests in `hubble.rs` load,
so the documented mapping and the tested behavior cannot drift apart.

## Fixture 1 — `DROPPED` TCP egress (the security-relevant case)

[`fixtures/hubble/flow_dropped.json`](../crates/sensors/fixtures/hubble/flow_dropped.json)

```json
{
  "flow": {
    "time": "2026-09-20T12:02:00Z",
    "verdict": "DROPPED",
    "drop_reason_desc": "POLICY_DENIED",
    "IP": { "source": "10.0.1.50", "destination": "198.51.100.200" },
    "l4": { "TCP": { "source_port": 54321, "destination_port": 443 } },
    "source": {
      "pod_name": "billing-service-789d-abc",
      "workloads": [{ "name": "billing-service", "kind": "Deployment" }]
    },
    "traffic_direction": "EGRESS"
  },
  "node_name": "worker-k8s-01"
}
```

| Raw Hubble field | Canonical `SecurityEvent` field | How it is derived |
|------------------|--------------------------------|-------------------|
| `flow.time` | `timestamp` | Parsed as RFC 3339 → `DateTime<Utc>` (falls back to now if absent). |
| `flow.verdict` | `event_type` = `network.hubble.<verdict>` (lower-cased); `severity` = `high` when `DROPPED`, else `low` | `is_dropped = verdict == "DROPPED"` drives both. |
| `flow.verdict` | `is_security_significant` | `true` only when dropped. |
| `flow.source.labels` (`app=`/`k8s:app=`) → `workloads[0].name` → `pod_name` | `app_id` (the **service**) | First match wins; the `k8s:` prefix is stripped from labels. Falls back to `hubble-monitored-service`. |
| `flow.IP.source` / `flow.l4.TCP.source_port` | `source.ip` / `source.port` | The flow's origin address. |
| `flow.l4.TCP` vs `flow.l4.UDP` → protocol | `source.process_name` = `<PROTOCOL>:<direction>` | `TCP`/`UDP`, else `IP`. |
| `flow.l4.<proto>.source_port` | `source.port` | Source port for the matched protocol. |
| `flow.IP.destination` + `flow.l4.<proto>.destination_port` | `action.endpoint` = `<dst>:<port>` | The resolved destination (the **endpoint**). |
| `flow.traffic_direction` | `action.method` | `EGRESS`/`INGRESS` — the **flow context**. |
| `flow.verdict` + `flow.drop_reason_desc` + protocol | `action.operation` = `<verdict>: <reason> (<protocol>)` | The policy verdict and its reason. |
| `flow.verdict` = `DROPPED` | `action.is_success` = `false` (else `true`) | A drop is not a success. |
| `node_name` | `source.sensor.sensor_id` | The Hubble node that observed the flow. |
| `flow.verdict` | `source.sensor.raw_event_type` = `flow_<verdict>` | Which raw family was matched. |
| whole object | `source.sensor.raw_payload` | The raw flow is retained for forensics. |

### Canonical event produced

```json
{
  "event_type": "network.hubble.dropped",
  "severity": "high",
  "app_id": "billing-service",
  "environment": "production",
  "source": {
    "sensor": {
      "sensor_type": "hubble",
      "raw_event_type": "flow_DROPPED",
      "sensor_id": "worker-k8s-01",
      "raw_payload": { "...": "the full flow above is retained" }
    },
    "ip": "10.0.1.50",
    "port": 54321,
    "process_name": "TCP:EGRESS"
  },
  "action": {
    "method": "EGRESS",
    "endpoint": "198.51.100.200:443",
    "is_success": false,
    "operation": "DROPPED: POLICY_DENIED (TCP)"
  },
  "is_security_significant": true
}
```

Note the `198.51.100.200` destination is a TEST-NET-1 address, not a real target. The
`billing-service` service name comes from `flow.source.workloads[0].name` (this fixture has no
`k8s:app=` label, so the workload path resolves it).

## Fixture 2 — `ALLOWED` UDP flow (the low-severity case)

[`fixtures/hubble/flow_allowed.json`](../crates/sensors/fixtures/hubble/flow_allowed.json)

```json
{
  "flow": {
    "time": "2026-09-20T12:04:15Z",
    "verdict": "ALLOWED",
    "IP": { "source": "10.0.2.10", "destination": "10.0.3.20" },
    "l4": { "UDP": { "source_port": 53000, "destination_port": 53 } },
    "source": {
      "labels": ["k8s:app=payments-service", "k8s:namespace=prod"],
      "workloads": [{ "name": "payments-service", "kind": "Deployment" }]
    },
    "traffic_direction": "EGRESS"
  },
  "node_name": "worker-k8s-02"
}
```

| Raw field | Canonical field | Note |
|-----------|-----------------|------|
| `flow.source.labels` = `k8s:app=payments-service` | `app_id` = `payments-service` | The `k8s:app=` label path resolves the service (distinct from the workload path in fixture 1). |
| `flow.verdict` = `ALLOWED` | `event_type` = `network.hubble.allowed`, `severity` = `low`, `is_security_significant` = `false` | An allowed flow is not significant. |
| `flow.l4.UDP` | `source.process_name` = `UDP:EGRESS` | UDP protocol label. |
| `flow.IP.destination` + `flow.l4.UDP.destination_port` | `action.endpoint` = `10.0.3.20:53` | A resolved DNS lookup destination. |
| `flow.verdict` = `ALLOWED` | `action.is_success` = `true` | An allowed flow is a success. |

## Schema-preservation tests

The adapter's fixture-backed tests live in
[`crates/sensors/src/hubble.rs`](../crates/sensors/src/hubble.rs)
(`schema_preserved_for_fixture_dropped_flow`, `schema_preserved_for_fixture_allowed_flow`).
They load the JSON files above and assert that the service, endpoint, protocol, and flow
context survive as the typed canonical fields — the "preserve sensor semantics" invariant in
[CONTRIBUTING.md](../../CONTRIBUTING.md). Together the two fixtures exercise all three
`app_id` resolution paths (label, workload, pod name) and both verdict outcomes. Running them:

```bash
cargo test -p security-control-plane-sensors hubble
```

A new Hubble flow shape is added by dropping a matching JSON file under
`crates/sensors/fixtures/hubble/` — the adapter already handles TCP/UDP, both verdicts, and the
label/workload/pod service-resolution cascade, so no downstream detection logic changes.
