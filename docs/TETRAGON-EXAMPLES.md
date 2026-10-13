# Tetragon telemetry: fixtures to canonical events

Tetragon (Cilium's eBPF runtime-security engine) emits JSON objects for
`process_exec` and `process_kprobe` events. The adapter in
[`crates/sensors/src/tetragon.rs`](../crates/sensors/src/tetragon.rs)
normalizes them into the canonical [`SecurityEvent`](../crates/common/src/models.rs)
shape that detection, correlation, and advisory all read.

This page shows two representative raw fixtures (kept under
[`crates/sensors/fixtures/tetragon/`](../crates/sensors/fixtures/tetragon/)) and maps each
raw field to the canonical field the adapter fills. The fixtures are the exact inputs the
schema-preservation tests in `tetragon.rs` load, so the documented mapping and the tested
behavior cannot drift apart.

## Fixture 1 — `process_exec` (a shell inside a container)

[`fixtures/tetragon/process_exec.json`](../crates/sensors/fixtures/tetragon/process_exec.json)

```json
{
  "process_exec": {
    "process": {
      "exec_id": "b3JnL2FwcC0xMjM=",
      "pid": 4821,
      "uid": 0,
      "binary": "/bin/sh",
      "arguments": "-i",
      "pod": {
        "namespace": "prod",
        "name": "billing-deployment-64d8f-xyz12",
        "container": {
          "id": "containerd://a83f9104c99e",
          "name": "billing-app"
        }
      }
    }
  },
  "node_name": "worker-k8s-01",
  "time": "2026-09-20T12:00:00Z"
}
```

| Raw Tetragon field | Canonical `SecurityEvent` field | How it is derived |
|--------------------|--------------------------------|-------------------|
| `node_name` | `source.sensor.sensor_id` | The Tetragon node that produced the event. |
| `time` | `timestamp` | Parsed as RFC 3339 → `DateTime<Utc>` (falls back to now if absent). |
| `process_exec` present | `event_type` = `kernel.process_exec` | Fixed for the exec family. |
| `process.binary` | `source.process_name` and `action.operation` (`exec: <binary>`) | The executed binary. |
| `process.arguments` | `action.endpoint` | Argument string, kept for the exec context. |
| `process.pid` | `source.pid` | Numeric PID. |
| `process.uid` | `actor` (`user_id` = `uid:<n>`, `role` = `root` when 0) | The executing user. |
| `process.pod.name` | `app_id` | Kubernetes hash suffix stripped (`billing-deployment-64d8f-xyz12` → `billing-deployment`). |
| `process.pod.container.id` | `source.container_id` | Container the process ran in. |
| `process.binary` (shell + in-container) | `severity` = `critical`, `is_security_significant` = `true` | `classify_binary` — a shell inside a container is the critical case. |
| whole object | `source.sensor.raw_payload` | The raw JSON is retained for forensics. |
| `process_exec.process` | `source.sensor.raw_event_type` = `process_exec` | Which raw family was matched. |

### Canonical event produced

```json
{
  "event_type": "kernel.process_exec",
  "severity": "critical",
  "app_id": "billing-deployment",
  "environment": "production",
  "actor": { "user_id": "uid:0", "role": "root" },
  "source": {
    "sensor": {
      "sensor_type": "tetragon",
      "raw_event_type": "process_exec",
      "sensor_id": "worker-k8s-01",
      "raw_payload": { "...": "the full object above is retained" }
    },
    "container_id": "containerd://a83f9104c99e",
    "pid": 4821,
    "process_name": "/bin/sh"
  },
  "action": { "endpoint": "-i", "is_success": true, "operation": "exec: /bin/sh" },
  "is_security_significant": true
}
```

## Fixture 2 — `process_kprobe` (a `connect()` kprobe on `curl`)

[`fixtures/tetragon/process_kprobe.json`](../crates/sensors/fixtures/tetragon/process_kprobe.json)

```json
{
  "process_kprobe": {
    "function_name": "sys_enter_connect",
    "process": {
      "pid": 5012,
      "binary": "/usr/bin/curl",
      "pod": {
        "namespace": "prod",
        "name": "crm-app",
        "container": {
          "id": "containerd://bb8812c",
          "name": "crm-app"
        }
      }
    }
  },
  "node_name": "worker-k8s-02",
  "time": "2026-09-20T12:05:00Z"
}
```

| Raw field | Canonical field | Note |
|-----------|-----------------|------|
| `process_kprobe.function_name` | `event_type` = `kernel.kprobe.<function_name>` | The kprobe symbol becomes the event-type suffix. |
| `process_kprobe.function_name` | `action.endpoint` and `action.operation` (`kprobe:<name>`) | The probed syscall context. |
| `process.pid` | `source.pid` | Numeric PID. |
| `process.binary` | `source.process_name` | The binary the probe fired in. |
| `pod.container.name` | `app_id` | No hash stripping for the kprobe family (plain pod name). |
| `pod.container.id` | `source.container_id` | Container id. |
| — | `severity` = `medium`, `is_security_significant` = `true` | Every kprobe is treated as significant at `medium`. |

## Schema-preservation tests

The adapter's fixture-backed tests live in
[`crates/sensors/src/tetragon.rs`](../crates/sensors/src/tetragon.rs)
(`schema_preserved_for_fixture_process_exec`, `schema_preserved_for_fixture_process_kprobe`).
They load the JSON files above and assert that the raw fields survive as the typed,
canonical fields — the "preserve sensor semantics" invariant in
[CONTRIBUTING.md](../../CONTRIBUTING.md). Running them:

```bash
cargo test -p security-control-plane-sensors tetragon
```

A new Tetragon event family (e.g. a future `process_openat` probe) is added by extending
`TetragonAdapter::parse_event` and dropping a matching JSON file under
`crates/sensors/fixtures/tetragon/` — no downstream detection logic changes.
