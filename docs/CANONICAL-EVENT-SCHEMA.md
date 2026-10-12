# Canonical Event Schema

Reference for the canonical security event produced by every sensor adapter and
consumed by validation, detection, correlation, and containment. The type is
`SecurityEvent` in [`crates/common/src/models.rs`](../crates/common/src/models.rs);
validation rules live in
[`crates/common/src/validation.rs`](../crates/common/src/validation.rs).

Each sensor (Hubble, Falco, Tetragon, the application agent, and the native
sensor) normalizes its raw payload into this single shape so that downstream
stages operate on one model while source-specific detail is preserved in
`source.sensor`.

```text
Hubble flow log ─► HubbleAdapter::parse_event ─┐
Falco rule match ─► FalcoAdapter::parse_event ──┤
Tetragon event ──► TetragonAdapter::parse_event ┤
App telemetry    ─► Agent SDK                ──► SecurityEvent ─► validate ─► engine
Native sensor    ─► normalizer               ──┘
```

## Top-level fields

| Field | Type | Required | Notes |
|---|---|---|---|
| `event_id` | `Uuid` | yes | Client-generated v4; set by `SecurityEvent::new`. Not settable by sensors after construction. |
| `timestamp` | `DateTime<Utc>` | yes | UTC. Validation rejects events more than 1 h in the future or 7 days in the past. |
| `app_id` | `String` | yes | The application identity. Required, non-empty, ≤ 128 chars. Sensors derive it from workload labels when no application identity is known (e.g. Hubble falls back to `hubble-monitored-service`). |
| `environment` | `String` | yes | Deployment environment label, e.g. `production`, `staging`. Required, non-empty. |
| `event_type` | `String` | yes | Normalized type, e.g. `http.request`, `network.hubble.dropped`, `falco.rule_match`. ≤ 128 chars. |
| `severity` | `Severity` | yes | One of `low`, `medium`, `high`, `critical` (snake_case on the wire). Adapters set a sensible default; the engine may override. |
| `actor` | `Option<ActorContext>` | no | Identity dimensions of the acting principal. `None` when no application-level actor is known (typical for pure network events). |
| `source` | `SourceContext` | yes | Where the signal originated. Always present; see below. |
| `action` | `Option<ActionContext>` | no | What happened (request, flow, syscall, rule match). `None` for events that carry no action context. |
| `resource` | `Option<ResourceContext>` | no | The object the action targeted. |
| `metadata` | `HashMap<String, Value>` | no | Free-form key/value escape hatch. Omitted from JSON when empty. |
| `is_security_significant` | `bool` | yes | Default `false`. Set by adapters when the event is already known to be security-meaningful (e.g. a dropped Hubble flow) so the selective-persistence filter can skip benign noise. |

## `ActorContext`

Identity dimensions for the acting principal. All fields optional.

| Field | Type | Notes |
|---|---|---|
| `user_id` | `Option<String>` | End-user or service-account identifier. |
| `role` | `Option<String>` | Application-level role label. |
| `session_id` | `Option<String>` | Session identifier for session-scoped correlation. |
| `auth_method` | `Option<String>` | `password`, `mfa`, `token`, `cert`, etc. |
| `client_fingerprint` | `Option<String>` | Stable client hash for cross-session identity. |

## `SourceContext`

Where the signal originated. All fields optional except `sensor`.

| Field | Type | Notes |
|---|---|---|
| `ip` | `Option<String>` | Source IP of the signal. |
| `port` | `Option<u16>` | Source port. |
| `user_agent` | `Option<String>` | Client user-agent string when available. |
| `sensor` | `SensorMetadata` | **Required** — which sensor produced the event (see below). |
| `container_id` | `Option<String>` | Container the signal was observed in. |
| `pid` | `Option<u32>` | Process identifier for runtime events. |
| `process_name` | `Option<String>` | Process name; adapters may pack protocol/direction here (e.g. Hubble stores `TCP:EGRESS`). |

## `SensorMetadata`

| Field | Type | Required | Notes |
|---|---|---|---|
| `sensor_type` | `SensorType` | yes | One of `agent`, `tetragon`, `falco`, `hubble`, `network`, `system`, `native_sensor`. |
| `raw_event_type` | `String` | yes | The source's native event type, e.g. `http_inbound`, `flow_DROPPED`. Validation rejects empty values. |
| `sensor_id` | `Option<String>` | no | The node or host that reported the event (e.g. `worker-k8s-01`). |
| `raw_payload` | `Option<Value>` | no | The original raw JSON. Preserved so downstream consumers can recover source-specific fields without re-querying the sensor. |

## `ActionContext`

What happened. All fields optional except `is_success`.

| Field | Type | Notes |
|---|---|---|
| `method` | `Option<String>` | HTTP method or traffic direction (`EGRESS`/`INGRESS` for network events). |
| `endpoint` | `Option<String>` | Target endpoint, e.g. `/api/v1/orders` or `198.51.100.200:443`. |
| `status_code` | `Option<u16>` | HTTP response code when known. |
| `duration_us` | `Option<u64>` | Request or operation duration in microseconds. |
| `is_success` | `bool` | Default `true`. Set to `false` when the action was denied, failed, or dropped. |
| `operation` | `Option<String>` | Human-readable operation summary, e.g. `DROPPED: POLICY_DENIED (TCP)`. |

## `ResourceContext`

The object an action targeted. All fields optional.

| Field | Type | Notes |
|---|---|---|
| `resource_type` | `Option<String>` | e.g. `order`, `payment`, `secret`. |
| `resource_id` | `Option<String>` | The specific instance identifier. |
| `sensitivity_tier` | `Option<String>` | `public`, `internal`, `confidential`, `restricted`. |

## Validation rules

Enforced by `validate_security_event` in `crates/common/src/validation.rs`:

| Rule | Limit |
|---|---|
| `app_id` non-empty and ≤ 128 chars | `MAX_ID_LENGTH = 128` |
| `environment` non-empty | — |
| `event_type` non-empty and ≤ 128 chars | `MAX_ID_LENGTH = 128` |
| `source.sensor.raw_event_type` non-empty | — |
| `timestamp` within `[now − 7 days, now + 1 hour]` | `MAX_PAST_SKEW_SECONDS = 7*86400`, `MAX_FUTURE_SKEW_SECONDS = 3600` |
| Serialized event ≤ 64 KB | `MAX_EVENT_SIZE_BYTES = 65536` |

## Wire format notes

- Enum variants serialize as **lowercase** (`Severity`) or **snake_case**
  (`SensorType`, `ActionContext` is a struct, not an enum).
- All optional fields use `#[serde(skip_serializing_if = "Option::is_none")]`
  so JSON payloads omit keys that are `None`.
- `metadata` and `is_security_significant` use `#[serde(default)]` and are
  omitted when empty / `false` respectively.

## Where to find the adapters

| Sensor | Adapter | Source file |
|---|---|---|
| Hubble | `HubbleAdapter` | [`crates/sensors/src/hubble.rs`](../crates/sensors/src/hubble.rs) |
| Falco | `FalcoAdapter` | [`crates/sensors/src/falco.rs`](../crates/sensors/src/falco.rs) |
| Tetragon | `TetragonAdapter` | [`crates/sensors/src/tetragon.rs`](../crates/sensors/src/tetragon.rs) |
| Application | Agent SDK | [`crates/agent-sdk/src/lib.rs`](../crates/agent-sdk/src/lib.rs) |
| Native sensor | normalizer | [`crates/sensor-native/src/normalizer.rs`](../crates/sensor-native/src/normalizer.rs) |
