# Canonical event schema

Every telemetry source — an in-app agent, an eBPF runtime sensor (Tetragon, Falco), a
network-flow adapter (Cilium Hubble), or a native kernel sensor — is normalized into one
shape before it is ingested, detected, correlated, or reasoned over. That shape is
**`SecurityEvent`**, defined in
[`crates/common/src/models.rs`](../crates/common/src/models.rs). This page is the
field-by-field reference for that schema: which fields are required versus optional on the
**wire**, how the enums serialize, and the validation contract that governs acceptable
values.

It is the *schema* reference — the field contract every sensor adapter must fill. The
per-sensor fixture → canonical mappings for Tetragon, Falco, and Hubble are documented in
their own example pages, which build directly on the schema defined here.

## Top-level `SecurityEvent`

| Field | Wire type | Required? | Meaning |
|-------|-----------|-----------|---------|
| `event_id` | `uuid` (v4) | **required** | Fresh v4 id generated at event creation; unique across the fleet. |
| `timestamp` | RFC 3339 UTC | **required** | When the source observed the event (the sensor's clock, normalized to UTC). |
| `app_id` | `string` | **required** | The application the event is attributed to. For a kernel sensor this is the host / container workload, not a service name. |
| `environment` | `string` | **required** | Deployment environment, e.g. `production`. |
| `event_type` | `string` | **required** | A dotted, source-specific type such as `http.request`, `kernel.process_exec`, or `network.hubble.dropped`. |
| `severity` | `low` \| `medium` \| `high` \| `critical` | **required** | The source's initial triage; detection may raise it downstream. |
| `actor` | object | optional | The **identity** dimension — the authenticated user / session that performed the action. Omitted from the wire when `None`. |
| `source` | object | **required** | Where the event came from. `source.sensor` is always present; the other members are optional. |
| `action` | object | optional | The discrete operation that happened (request, exec, kprobe). Omitted when `None`. |
| `resource` | object | optional | A named target resource, when the event is about one. Omitted when `None`. |
| `metadata` | object (`map<string, value>`) | optional | Source-specific extras (e.g. `ppid`, `uid`, `comm` from a kernel event). Omitted when empty. |
| `is_security_significant` | `bool` | **required** | The source's own "this matters" flag. Drives the selective-persistence filter. Defaults to `false` on deserialize. |

> **The "absence is meaningful" contract.** Optional fields use
> `#[serde(skip_serializing_if = "Option::is_none")]`, so a field that is not present in
> the wire JSON genuinely means "not known / not set" — not "empty string" or "zero". An
> adapter that does not know the `pid` omits `source.pid` entirely; it does not send
> `"pid": null` or `0`.

## `Severity`

`#[serde(rename_all = "lowercase")]` — the wire values are the exact lower-case strings:

`low`, `medium`, `high`, `critical`.

These carry an implicit ordering (`Low < Medium < High < Critical`); the model derives
`PartialOrd`/`Ord` so downstream logic can compare and take the max.

## `SensorType`

`#[serde(rename_all = "snake_case")]` — the wire values:

| Rust variant | Wire value | Emitted by |
|--------------|------------|------------|
| `Agent` | `agent` | The in-app `agent-sdk` (HTTP request telemetry). |
| `Tetragon` | `tetragon` | Cilium Tetragon eBPF runtime events. |
| `Falco` | `falco` | Falco runtime-security rule alerts. |
| `Hubble` | `hubble` | Cilium Hubble L3/L4/L7 flow logs. |
| `Network` | `network` | Generic network telemetry. |
| `System` | `system` | Host / system-level telemetry. |
| `NativeSensor` | `native_sensor` | The project's native kernel sensor (`sensor-native`). |

## `source` (`SourceContext`)

`source.sensor` is the only required member; everything else is optional and omitted when
unknown.

| Field | Wire type | Required? | Notes |
|-------|-----------|-----------|-------|
| `sensor.sensor_type` | `SensorType` | **required** | One of the wire values above. |
| `sensor.raw_event_type` | `string` | **required** | The source's own event name (`express_middleware`, `process_exec`, `flow_DROPPED`, …). |
| `sensor.sensor_id` | `string` | optional | Identifies the individual sensor instance, for traceability. |
| `sensor.raw_payload` | `json value` | optional | The un-parsed source payload, kept for forensics. |
| `ip` | `string` | optional | Network source address. |
| `port` | `u16` | optional | Network source port. |
| `user_agent` | `string` | optional | HTTP client user-agent, when present. |
| `container_id` | `string` | optional | The container the process ran in, when known. |
| `pid` | `u32` | optional | Process id (runtime provenance). |
| `process_name` | `string` | optional | The process / binary, or a protocol+direction label for flow events. |

## `actor` (`ActorContext`) — the identity dimension

All members are optional. A completely empty `actor` block is omitted from the wire.

| Field | Wire type | Notes |
|-------|-----------|-------|
| `user_id` | `string` | The acting user. eBPF adapters may use `uid:<n>` or the process user name. |
| `role` | `string` | e.g. `admin`, `root`, `editor`. |
| `session_id` | `string` | The session for the authenticated user. |
| `auth_method` | `string` | How the user was authenticated (e.g. `password`). |
| `client_fingerprint` | `string` | A device / browser fingerprint, when captured. |

## `action` (`ActionContext`) — the discrete operation

| Field | Wire type | Required? | Notes |
|-------|-----------|-----------|-------|
| `method` | `string` | optional | HTTP method, or a flow direction (`EGRESS`/`INGRESS`) for network events. |
| `endpoint` | `string` | optional | The target endpoint; for exec/kprobe events it carries the argument or kprobe symbol. |
| `status_code` | `u16` | optional | HTTP / verdict status code. |
| `duration_us` | `u64` | optional | Operation duration in microseconds. |
| `is_success` | `bool` | **required** | Always present. `true` for a completed / allowed operation, `false` for a drop, failure, or unauthorized access. |
| `operation` | `string` | optional | A short human-readable label (e.g. `exec: /bin/sh`, `DROPPED: POLICY_DENIED (TCP)`). |

## `resource` (`ResourceContext`)

All optional; an empty block is omitted from the wire.

| Field | Wire type | Notes |
|-------|-----------|-------|
| `resource_type` | `string` | e.g. `record`, `file`, `endpoint`. |
| `resource_id` | `string` | The identifier of the resource. |
| `sensitivity_tier` | `string` | A data-classification tier for the targeted resource. |

## Validation contract

`SecurityEvent` is checked by `validate_security_event`
([`crates/common/src/validation.rs`](../crates/common/src/validation.rs)) before it is
accepted. The enforced rules, and the constants they come from:

| Check | Rule | Constant |
|-------|------|----------|
| `app_id` | Non-empty after `trim`; length ≤ 128 | `MAX_ID_LENGTH` = 128 |
| `environment` | Non-empty after `trim` | — |
| `event_type` | Non-empty after `trim`; length ≤ 128 | `MAX_ID_LENGTH` = 128 |
| `source.sensor.raw_event_type` | Non-empty after `trim` | — |
| `timestamp` | Within **[now − 7 days, now + 1 hour]** | `MAX_PAST_SKEW_SECONDS` = 7 · 86400, `MAX_FUTURE_SKEW_SECONDS` = 3600 |
| whole payload | Serialized size ≤ 64 KB | `MAX_EVENT_SIZE_BYTES` = 65 536 |

Violations return a typed `ValidationError` (`MissingField`, `FieldTooLong`,
`TimestampSkew`, `PayloadTooLarge`) rather than panicking — an out-of-contract event is
rejected, not silently mutated. The timestamp window is why a sensor with a badly skewed
clock is rejected instead of silently poisoning sliding-window counts.

> Note: `metadata` and `is_security_significant` are not part of the required-field set —
> `metadata` defaults to empty and `is_security_significant` defaults to `false` on
> deserialize, so a minimal valid event still carries a well-defined value for both.

## Wire name convention

All field names serialize in their **snake_case Rust names** (the structs have no
`rename_all`), so the wire keys are exactly the column names above: `event_id`,
`app_id`, `event_type`, `is_security_significant`, `container_id`, `process_name`, and so
on. Only the two enums are renamed: `Severity` → lowercase, `SensorType` → snake_case.

## Keeping this page in sync

- Field additions/removals, and any change to a `serde` attribute on a model in
  `crates/common/src/models.rs`, must be reflected in the matching table row and in the
  "absence is meaningful" note in the same commit.
- Threshold and limit changes in `crates/common/src/validation.rs` must update the
  Validation contract table (the constants are named there on purpose).
- Enum value changes ripple to every sensor adapter (their adapters and example
  fixtures quote the wire values in this table).
