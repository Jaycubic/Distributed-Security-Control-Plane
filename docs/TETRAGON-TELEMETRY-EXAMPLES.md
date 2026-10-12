# Tetragon Telemetry Examples

Representative Cilium Tetragon process-telemetry fixtures and how they map into
the [canonical event model](ARCHITECTURE.md#canonical-event-model). The
adapter is `TetragonAdapter` in
[`crates/sensors/src/tetragon.rs`](../crates/sensors/src/tetragon.rs); raw
events are posted to `POST /api/v1/sensors/tetragon`.

Tetragon emits process-level eBPF events. This adapter handles two event
families, chosen by which top-level key is present:

- `process_exec` — a process was executed.
- `process_kprobe` — a traced kernel probe fired on a running process.

The full raw object is preserved in `source.sensor.raw_payload`, so schema
preservation is intact (the sensor-fidelity invariant).

## Shared extraction

| Canonical field | Tetragon source | Mapping |
|---|---|---|
| `environment` | — | Always `production` in this adapter |
| `source.sensor.sensor_type` | — | `tetragon` |
| `source.sensor.sensor_id` | `node_name` | The reporting node, when present |
| `source.sensor.raw_payload` | whole raw object | Preserved |
| `source.pid` | `process.pid` (or `process_kprobe.process.pid`) | Process id |
| `source.container_id` | `process.pod.container.id` | Container, when present |
| `source.process_name` | `process.binary` | Executed binary |

## `process_exec` mapping

| Canonical field | Tetragon source | Mapping |
|---|---|---|
| `event_type` | — | `kernel.process_exec` |
| `app_id` | `process.pod.name` (K8s hash suffix stripped), else `process.pod.container.name`, else `container-workload` | e.g. `billing-service-64d8f-xyz12` → `billing-service` |
| `severity` / `is_security_significant` | `process.binary` + whether in a container | See the classification table below |
| `actor.user_id` | `process.uid` | `uid:{uid}`; `role` is `root` when `uid == 0` |
| `action.endpoint` | `process.arguments` | The argument string |
| `action.operation` | `process.binary` | `exec: {binary}` |
| `action.is_success` | — | `true` (exec succeeded) |

### Binary classification

`classify_binary` drives both the severity and the `is_security_significant`
flag for a `process_exec`:

| Binary (case-insensitive) | In a container | Severity | Significant |
|---|---|---|---|
| shell (`/sh`, `/bash`, `/zsh`, `sh`, `bash`) | yes | `critical` | `true` |
| shell | no | `medium` | `false` |
| netcat (`/nc`, `/ncat`, `/socat`, `nc`) | any | `critical` | `true` |
| fetcher (`/curl`, `/wget`, `/python`) | yes | `high` | `true` |
| fetcher | no | `high` | `false` |
| anything else | — | `low` | `false` |

The K8s suffix strip keeps a `billing-deployment-64d8f-xyz12` pod name usable as
the app id: trailing 4–10 char alphanumeric segments that contain a digit are
treated as ReplicaSet/Deployment hashes and removed.

## Example 1 — root shell inside a container (critical)

Raw Tetragon `process_exec` event:

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
        "container": { "id": "containerd://a83f9104c99e", "name": "billing-app" }
      }
    }
  },
  "node_name": "worker-k8s-01",
  "time": "2026-09-20T12:00:00Z"
}
```

Normalized canonical event (`null` / `None` omitted):

```json
{
  "event_type": "kernel.process_exec",
  "severity": "critical",
  "app_id": "billing-deployment",
  "environment": "production",
  "actor": { "user_id": "uid:0", "role": "root" },
  "source": {
    "container_id": "containerd://a83f9104c99e",
    "pid": 4821,
    "process_name": "/bin/sh",
    "sensor": {
      "sensor_type": "tetragon",
      "raw_event_type": "process_exec",
      "sensor_id": "worker-k8s-01",
      "raw_payload": { "<full raw object, preserved>" }
    }
  },
  "action": {
    "endpoint": "-i",
    "operation": "exec: /bin/sh",
    "is_success": true
  },
  "is_security_significant": true
}
```

The pod name `billing-deployment-64d8f-xyz12` is reduced to `billing-deployment`
by the suffix strip. A root shell inside a container is the highest-severity
path: `critical` and security-significant.

## Example 2 — traced connect kprobe on an external fetch

Raw Tetragon `process_kprobe` event:

```json
{
  "process_kprobe": {
    "function_name": "sys_enter_connect",
    "process": {
      "pid": 5012,
      "binary": "/usr/bin/curl",
      "pod": { "container": { "id": "containerd://bb8812c", "name": "crm-app" } }
    }
  },
  "node_name": "worker-k8s-02",
  "time": "2026-09-20T12:05:00Z"
}
```

Normalized:

```json
{
  "event_type": "kernel.kprobe.sys_enter_connect",
  "severity": "medium",
  "app_id": "crm-app",
  "environment": "production",
  "source": {
    "container_id": "containerd://bb8812c",
    "pid": 5012,
    "process_name": "/usr/bin/curl",
    "sensor": {
      "sensor_type": "tetragon",
      "raw_event_type": "process_kprobe",
      "sensor_id": "worker-k8s-02"
    }
  },
  "action": {
    "endpoint": "sys_enter_connect",
    "operation": "kprobe:sys_enter_connect",
    "is_success": true
  },
  "is_security_significant": true
}
```

For `process_kprobe`, `app_id` comes from the container name (`crm-app`)
because there is no pod name to strip; the event type is
`kernel.kprobe.{function_name}`, severity is fixed at `medium`, and kprobe
events are always security-significant.

## Ingestion notes

- An event with neither `process_exec` nor `process_kprobe` is rejected with
  `TetragonParseError::MissingEventField`.
- A missing or unparseable `time` falls back to the ingest timestamp.
- Both fixtures mirror the Tetragon cases in
  [`tests/test_phase5_sensors.py`](../tests/test_phase5_sensors.py)
  (`test_01_tetragon_process_exec_ingest_and_normalization` and the kprobe
  coverage) and the unit tests in `crates/sensors/src/tetragon.rs`.
