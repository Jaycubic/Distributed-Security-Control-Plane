# Falco telemetry: fixtures to canonical events

Falco (the Falco / CNCF runtime-security project) emits JSON alerts when a
detection rule fires. The adapter in [`crates/sensors/src/falco.rs`](../crates/sensors/src/falco.rs)
normalizes each alert into the canonical [`SecurityEvent`](../crates/common/src/models.rs)
shape that detection, correlation, and advisory all read.

This page shows two representative raw fixtures (kept under
[`crates/sensors/fixtures/falco/`](../crates/sensors/fixtures/falco/)) and maps each raw field to the
canonical field the adapter fills. The fixtures are the exact inputs the
schema-preservation tests in `falco.rs` load, so the documented mapping and the tested
behavior cannot drift apart.

## Fixture 1 — `Terminal shell in container` (Critical)

[`fixtures/falco/terminal_shell_in_container.json`](../crates/sensors/fixtures/falco/terminal_shell_in_container.json)

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

| Raw Falco field | Canonical `SecurityEvent` field | How it is derived |
|-----------------|--------------------------------|-------------------|
| `rule` | `event_type` = `runtime.falco.<rule>` (lower-cased, spaces → `_`) and `action.operation` | The fired rule name. |
| `priority` | `severity` (via `map_priority`: `Critical`/`Alert`/`Emergency` → `critical`, `Error`/`Warning` → `high`, `Notice` → `medium`, else `low`) | Falco syslog priorities. |
| `time` | `timestamp` | Parsed as RFC 3339 → `DateTime<Utc>` (falls back to now if absent). |
| `output_fields.container.name` (fallback `k8s.pod.name`) | `app_id` | The workload the alert is attributed to. |
| `output_fields.container.id` | `source.container_id` | Container the process ran in. |
| `output_fields.proc.name` | `source.process_name` | The executed process. |
| `output_fields.proc.pid` | `source.pid` | Numeric PID. |
| `output_fields.proc.cmdline` | `action.endpoint` | The full command line. |
| `output_fields.user.name` | `actor` (`user_id` = name, `role` = `root` when `root`) | The acting user. |
| `output_fields.fd.rip` / `fd.rport` | `source.ip` / `source.port` | Remote network endpoint, when present. |
| `priority` ≠ `low` | `is_security_significant` = `true` | Any non-low alert is significant. |
| whole object | `source.sensor.raw_payload` | The raw alert is retained for forensics. |
| — | `source.sensor.raw_event_type` = `rule_alert`, `sensor_id` = `falco-engine` | Fixed for the Falco family. |

### Canonical event produced

```json
{
  "event_type": "runtime.falco.terminal_shell_in_container",
  "severity": "critical",
  "app_id": "billing-app",
  "environment": "production",
  "actor": { "user_id": "root", "role": "root" },
  "source": {
    "sensor": {
      "sensor_type": "falco",
      "raw_event_type": "rule_alert",
      "sensor_id": "falco-engine",
      "raw_payload": { "...": "the full alert above is retained" }
    },
    "container_id": "b43f9a12c",
    "pid": 2841,
    "process_name": "sh",
    "ip": "198.51.100.200",
    "port": 443
  },
  "action": {
    "endpoint": "sh -i",
    "is_success": false,
    "operation": "Terminal shell in container"
  },
  "is_security_significant": true
}
```

## Fixture 2 — `Sensitive file access` (Notice)

[`fixtures/falco/sensitive_file_access.json`](../crates/sensors/fixtures/falco/sensitive_file_access.json)

```json
{
  "uuid": "9f2c77d8-1a3e-4b9c-8d0a-77e0f1c2d345",
  "time": "2026-09-20T12:03:30Z",
  "rule": "Sensitive file access",
  "priority": "Notice",
  "output_fields": {
    "container.id": "cc01aa22",
    "container.name": "auth-service",
    "proc.name": "cat",
    "proc.pid": 1204,
    "proc.cmdline": "cat /etc/shadow",
    "user.name": "deployer"
  },
  "source": "syscall"
}
```

| Raw field | Canonical field | Note |
|-----------|-----------------|------|
| `rule` | `event_type` = `runtime.falco.sensitive_file_access` | Lower-cased rule name. |
| `priority` = `Notice` | `severity` = `medium`, `is_security_significant` = `true` | `Notice` maps to `medium`, which is significant. |
| `user.name` = `deployer` | `actor.user_id` = `deployer`, `actor.role` = `None` | A non-root user still yields an actor, just without the `root` role. |
| (no `fd.*` fields) | `source.ip` / `source.port` = `None` | Absent network fields stay absent — the optional-field contract is preserved, not invented. |

## Schema-preservation tests

The adapter's fixture-backed tests live in
[`crates/sensors/src/falco.rs`](../crates/sensors/src/falco.rs)
(`schema_preserved_for_fixture_critical_alert`, `schema_preserved_for_fixture_notice_alert`).
They load the JSON files above and assert that the raw fields survive as the typed,
canonical fields — the "preserve sensor semantics" invariant in
[CONTRIBUTING.md](../../CONTRIBUTING.md). Running them:

```bash
cargo test -p security-control-plane-sensors falco
```

A new Falco rule is added by dropping a matching JSON file under
`crates/sensors/fixtures/falco/` — the adapter already handles any `rule`/`priority`
and the optional `output_fields`, so no downstream detection logic changes.
