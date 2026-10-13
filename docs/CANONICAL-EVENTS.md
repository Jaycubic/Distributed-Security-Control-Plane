# Canonical telemetry events

Every telemetry source in the system — an in-app agent, a kernel/runtime sensor, or a
network flow log — is normalized into a single shape, the **canonical unified security
event** (`SecurityEvent`, defined in [`crates/common/src/models.rs`](../crates/common/src/models.rs)).
Detection, correlation, and advisory all read that one schema, so a downstream consumer
never has to know which sensor produced a finding.

This page shows one representative event from each of the three telemetry families the
project ships — **application**, **runtime**, and **network** — with the required
fields, the source metadata, the timestamp, and the identity (actor) fields made
explicit. Field names are the wire names, i.e. the JSON the control plane actually
receives (lower-cased severity/snake-case sensor types come from the `serde`
`rename_all` attributes on the model). The examples show only the blocks each family
populates; `actor`, `action`, `resource`, and `metadata` are omitted from the wire
entirely when empty, so their absence below is meaningful, not a typo.

## Field reference

Fields that are always present on a canonical event:

| Field | Type | Meaning |
|-------|------|---------|
| `event_id` | `uuid` | A fresh v4 id generated at event creation; unique across the fleet. |
| `timestamp` | RFC 3339 UTC | When the source observed the event (the sensor's clock, normalized to UTC). |
| `app_id` | string | The application this event is attributed to. For a kernel sensor this is the host `hostname`. |
| `environment` | string | Deployment environment, e.g. `production`. |
| `event_type` | string | A dotted, source-specific type such as `http.request`, `kernel.execve`, or `network.hubble.dropped`. |
| `severity` | `low` / `medium` / `high` / `critical` | The source's initial triage; downstream detection may raise it. |
| `source` | object | Where the event came from — see the sub-table below. |
| `is_security_significant` | bool | The source's own "this matters" flag; the selective-persistence filter uses it. |

Source metadata (`source`), with the one member that is always present (`sensor`) and the
optional ones that apply to a given family:

| Field | Optional? | Notes |
|-------|-----------|-------|
| `source.sensor.sensor_type` | required | `agent` \| `tetragon` \| `falco` \| `hubble` \| `network` \| `system` \| `native_sensor`. |
| `source.sensor.raw_event_type` | required | The source's own event name (`express_middleware`, `execve`, `flow_DROPPED`, …). |
| `source.sensor.sensor_id` | optional | Identifies the individual sensor instance, for traceability. |
| `source.sensor.raw_payload` | optional | The un-parsed source payload, kept when the adapter wants it for forensics. |
| `source.ip` / `source.port` | optional | Network source address. |
| `source.pid` / `source.process_name` | optional | Runtime (process) provenance. |
| `source.container_id` | optional | Container the process ran in, when known. |
| `source.user_agent` | optional | HTTP client user-agent, when present. |

Optional context blocks (omitted from the wire when empty):

| Block | Fields | When it is present |
|-------|--------|--------------------|
| `actor` | `user_id`, `role`, `session_id`, `auth_method`, `client_fingerprint` | Application events that carry an authenticated user / session (the **identity** dimension). |
| `action` | `method`, `endpoint`, `status_code`, `duration_us`, `operation`, `is_success` | Requests and other discrete operations. |
| `resource` | `resource_type`, `resource_id`, `sensitivity_tier` | When the event targets a named resource. |
| `metadata` | arbitrary key/value | Source-specific extras (e.g. `ppid`, `uid`, `comm` from a kernel event). |

---

## 1. Application telemetry

An in-app agent (e.g. the Node/Express emitter in `services/mock-apps/node_app/emitter.js`)
records each HTTP request as a `http.request` event. A request that hit an auth-sensitive
path carries the acting user in `actor` — the identity dimension the downstream correlator
joins on. Here there is no `resource` or `metadata` block, so neither appears.

```json
{
  "event_id": "3f2a…c1",
  "timestamp": "2026-09-20T12:01:47.312Z",
  "app_id": "application-b-api",
  "environment": "production",
  "event_type": "http.request",
  "severity": "medium",
  "actor": {
    "user_id": "u-8841",
    "session_id": "sess-5f2",
    "role": "editor"
  },
  "source": {
    "ip": "10.0.4.17",
    "sensor": {
      "sensor_type": "agent",
      "raw_event_type": "express_middleware"
    }
  },
  "action": {
    "method": "POST",
    "endpoint": "/admin/refunds",
    "status_code": 403,
    "duration_us": 1840,
    "is_success": false
  },
  "is_security_significant": true
}
```

Read it as: user `u-8841` (session `sess-5f2`, role `editor`) made a `POST /admin/refunds`
that came back `403` — a `403` on an auth path marks the event security-significant, so
the source raises severity to `medium` and sets `is_security_significant`.

## 2. Runtime telemetry

A kernel sensor (`crates/sensor-native`) normalizes an `execve` into `kernel.execve`.
Process provenance lives in `source.pid` / `source.process_name`, and kernel-specific
context (parent pid, the exec'd binary, uid, and `comm`) rides in `metadata`. There is no
`actor` — a local process is not an authenticated web user — and no `action`/`resource`.

```json
{
  "event_id": "9b1d…e7",
  "timestamp": "2026-09-20T12:01:52.004Z",
  "app_id": "prod-web-01",
  "environment": "production",
  "event_type": "kernel.execve",
  "severity": "high",
  "source": {
    "pid": 40213,
    "process_name": "/usr/bin/sudo",
    "sensor": {
      "sensor_type": "native_sensor",
      "raw_event_type": "execve",
      "sensor_id": "native-sensor-prod-web-01"
    }
  },
  "metadata": {
    "comm": "sudo",
    "filename": "/usr/bin/sudo",
    "ppid": 40100,
    "uid": 0
  },
  "is_security_significant": true
}
```

Note `app_id` is the **host** (`prod-web-01`), not a service — a runtime sensor attributes
events to the machine it runs on. Executing `sudo` classifies the event `high`
(`classify_exec_severity` treats privilege-escalation binaries as high-risk), and the
kernel sensor sets `is_security_significant` whenever severity reaches `medium` or above.

## 3. Network telemetry

A Hubble flow adapter (`crates/sensors/src/hubble.rs`) turns a L3/L4/L7 flow log into a
`network.hubble.*` event. A `DROPPED` verdict is the security-relevant case: it is marked
significant, its severity is raised to `high`, and the policy verdict plus the destination
are captured in `action`.

```json
{
  "event_id": "c51a…40",
  "timestamp": "2026-09-20T12:02:00.000Z",
  "app_id": "billing-service",
  "environment": "production",
  "event_type": "network.hubble.dropped",
  "severity": "high",
  "source": {
    "ip": "10.0.1.50",
    "port": 54321,
    "process_name": "TCP:EGRESS",
    "sensor": {
      "sensor_type": "hubble",
      "raw_event_type": "flow_DROPPED",
      "sensor_id": "worker-k8s-01"
    }
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

The `198.51.100.200` destination here is from the test fixture in
`crates/sensors/src/hubble.rs` (a TEST-NET-1 address, not a real target). The adapter
resolves `app_id` from the source workload's `app=` label, falling back to the workload or
pod name when no label is set.

---

## Why the shape is stable

All three examples are different telemetry from very different producers, yet every
downstream component — detection rules, the correlation graph, and the advisory gate —
operates on the same `SecurityEvent` fields above. Adding a new sensor means writing an
adapter that fills in this schema (typically populating `source.sensor`, `app_id`,
`event_type`, and optionally `actor`/`action`/`resource`), not touching the detection
logic. The field-by-field definitions live in
[`crates/common/src/models.rs`](../crates/common/src/models.rs).
