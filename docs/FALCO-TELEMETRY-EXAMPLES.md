# Falco Telemetry Examples

Representative Falco runtime-security alert fixtures and how they map into the
[canonical event model](ARCHITECTURE.md#canonical-event-model). The adapter is
`FalcoAdapter` in
[`crates/sensors/src/falco.rs`](../crates/sensors/src/falco.rs); raw alerts are
posted to `POST /api/v1/sensors/falco`.

A Falco alert is a rule match: it carries the rule name, a syslog-style
`priority`, an `output` line, and a flat `output_fields` map keyed by dotted
field names. The adapter normalizes these into one canonical event and preserves
the full raw object in `source.sensor.raw_payload`.

## What the adapter extracts

| Canonical field | Falco source | Mapping |
|---|---|---|
| `event_type` | `rule` | `runtime.falco.{rule_lowercased, spaces→_}` |
| `severity` | `priority` | `emergency`/`alert`/`critical` → `critical`; `error`/`warning` → `high`; `notice` → `medium`; anything else (e.g. `informational`) → `low` |
| `app_id` | `output_fields["container.name"]`, else `output_fields["k8s.pod.name"]`, else `falco-monitored-workload` | First present wins |
| `environment` | — | Always `production` in this adapter |
| `source.sensor.sensor_type` | — | `falco` |
| `source.sensor.raw_event_type` | — | Always `rule_alert` |
| `source.sensor.sensor_id` | — | Fixed `falco-engine` |
| `source.sensor.raw_payload` | whole raw object | Preserved |
| `source.container_id` | `output_fields["container.id"]` | Container the alert fired in |
| `source.pid` | `output_fields["proc.pid"]` | Process id, when present |
| `source.process_name` | `output_fields["proc.name"]` | Executed process |
| `source.ip` | `output_fields["fd.rip"]` | Remote IP, when the rule captured a file descriptor |
| `source.port` | `output_fields["fd.rport"]` | Remote port, when captured |
| `actor.user_id` | `output_fields["user.name"]` | Present only when a user field is captured |
| `actor.role` | `user.name == "root"` | `root` when the user is root, else omitted |
| `action.endpoint` | `output_fields["proc.cmdline"]` | The full command line, when present |
| `action.operation` | `rule` | The rule name |
| `action.is_success` | — | Always `false` for a rule match (Falco alerts are findings) |
| `is_security_significant` | severity | `true` whenever the mapped severity is above `low` |

`output_fields` is a plain flat map; any key that is absent simply yields a
`None` and is omitted from the JSON (the fields are `Option`-typed).

## Example 1 — critical container shell alert

Raw Falco alert:

```json
{
  "uuid": "4c45a6c1-5c3b-483d-9be2-44a69b764264",
  "time": "2026-09-20T12:01:00Z",
  "rule": "Terminal shell in container",
  "priority": "Critical",
  "output": "A shell was spawned in container (user=root container_id=b43f9a12c cmdline=sh -i)",
  "output_fields": {
    "container.id": "b43f9a12c",
    "container.name": "billing-app",
    "proc.name": "sh",
    "proc.pid": 2841,
    "proc.cmdline": "sh -i",
    "user.name": "root",
    "fd.rip": "198.51.100.200",
    "fd.rport": 443
  },
  "source": "syscall"
}
```

Normalized canonical event (`null` / `None` omitted):

```json
{
  "event_type": "runtime.falco.terminal_shell_in_container",
  "severity": "critical",
  "app_id": "billing-app",
  "environment": "production",
  "actor": { "user_id": "root", "role": "root" },
  "source": {
    "ip": "198.51.100.200",
    "port": 443,
    "container_id": "b43f9a12c",
    "pid": 2841,
    "process_name": "sh",
    "sensor": {
      "sensor_type": "falco",
      "raw_event_type": "rule_alert",
      "sensor_id": "falco-engine",
      "raw_payload": { "<full raw object, preserved>" }
    }
  },
  "action": {
    "endpoint": "sh -i",
    "operation": "Terminal shell in container",
    "is_success": false
  },
  "is_security_significant": true
}
```

`event_type` is built from the rule name (lower-cased, spaces to underscores).
Because the priority is `Critical`, the event is both `critical` severity and
security-significant.

## Example 2 — informational rule with no user or fd fields

```json
{
  "time": "2026-09-20T13:00:00Z",
  "rule": "Read sensitive file",
  "priority": "Informational",
  "output": "Sensitive file read (name=/etc/passwd)",
  "output_fields": {
    "container.name": "auth-portal",
    "k8s.pod.name": "auth-portal-7c981-jk22m",
    "proc.name": "cat"
  }
}
```

Normalized:

```json
{
  "event_type": "runtime.falco.read_sensitive_file",
  "severity": "low",
  "app_id": "auth-portal",
  "environment": "production",
  "source": {
    "process_name": "cat",
    "sensor": { "sensor_type": "falco", "raw_event_type": "rule_alert", "sensor_id": "falco-engine" }
  },
  "action": {
    "operation": "Read sensitive file",
    "is_success": false
  },
  "is_security_significant": false
}
```

Observations:

- `app_id` resolves to `auth-portal` from `container.name`; the
  `k8s.pod.name` value is only a fallback and is not used here.
- No `user.name`, so `actor` is absent. No `fd.rip` / `fd.rport`, so `ip`
  and `port` are omitted. No `proc.cmdline`, so `action.endpoint` is omitted.
- `Informational` maps to `low`, so `is_security_significant` is `false`.

## Ingestion notes

- A payload without a `rule` string is rejected with
  `FalcoParseError::MissingField("rule")`; every other field is optional.
- A missing or unparseable `time` falls back to the ingest timestamp.
- `sensor_id` is always `falco-engine` in this adapter (Falco alerts do not
  carry the reporting node the way Hubble/Tetragon do).
- These fixtures mirror the Falco case exercised by
  [`tests/test_phase5_sensors.py`](../tests/test_phase5_sensors.py)
  (`test_02_falco_container_shell_ingest_and_normalization`).
