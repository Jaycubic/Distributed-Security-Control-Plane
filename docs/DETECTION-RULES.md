# Sliding-window detection rules

This page documents the deterministic, sliding-window detection rules that ship
in the Phase 2 engine (`crates/engine/src/rules/`), and the hot-state primitive
they are built on (`crates/engine/src/state/`). It is a **reference** kept in
lockstep with the implementation: every default value below is the exact value in
the corresponding `Default` impl, and the behavior is pinned by
[`tests/test_phase2_engine.py`](../tests/test_phase2_engine.py) and the engine unit
tests in `crates/engine/src/lib.rs` (`test_brute_force_detection_and_incident_escalation`,
`test_kernel_anomaly_detection`, `test_memory_hot_state_sliding_window`).

The goal of #2 is synchronization: if a threshold, window, or rule name in the
code changes, the matching line here changes in the same PR.

## How the rules work

Each rule implements the `Rule` trait (`rules/mod.rs`) and is evaluated against
the **canonical `SecurityEvent`** model plus a `HotStateStore`. The engine
(`evaluator.rs`, `RuleEngine::with_default_rules`) registers the six rules below
in this order and runs every one against each event:

| Order | Rule struct | `id()` | Signal name |
|-------|-------------|--------|-------------|
| 1 | `BruteForceRule` | `RULE_BRUTE_FORCE` | Credential Brute-Force / Password Spray |
| 2 | `RapidApiEnumerationRule` | `RULE_API_ENUMERATION` | Rapid API / Directory Enumeration Scan |
| 3 | `UnauthorizedBurstRule` | `RULE_UNAUTHORIZED_BURST` | Unauthorized Access Burst (401/403) |
| 4 | `MassDataScrapingRule` | `RULE_MASS_DATA_SCRAPING` | Mass Data Scraping / Export Burst |
| 5 | `KernelAnomalyRule` | `RULE_KERNEL_ANOMALY` | Suspicious Container / Kernel Execution |
| 6 | `PrivilegeCreepRule` | `RULE_PRIVILEGE_CREEP` | Administrative Privilege Creep / Probe |

When a rule fires it emits a `SecuritySignal` carrying a **risk weight**. The
engine attributes the signal to a target entity (`user:` → `ip:` → `app:`, in
that preference order), accumulates the weight into the entity's risk score with
a 1-hour TTL, and either escalates the existing incident or opens a new one.

## The sliding-window primitive

Rules don't keep their own counters — they call into `HotStateStore`
(`state/mod.rs`). Two backends implement the same trait: `MemoryHotState`
(deterministic, zero-dependency, used by the local single-node mode and all the
tests) and `RedisHotState` (the distributed multi-node mode). Two of those
operations matter to these rules:

- **`record_hit(key, now_ms, window_ms)`** — appends `now_ms` to a per-key sliding
  window, evicting entries older than `now_ms - window_ms`, and returns the number
  of hits currently **inside** the window. In-memory it is a `VecDeque` of
  timestamps; in Redis it is a zset with a score-cutoff `zrembyscore` and a TTL.
  This is the mechanism behind rules 1, 3, and 4 (count-of-events-in-window).
- **`record_distinct(set_key, item, ttl_secs)`** — records a distinct item in a
  per-key set and returns the distinct count. Used only by rule 2 to count
  *different* endpoints probed, not just total requests.

Both the in-memory and Redis backends evict expired entries on the next
operation, so a key that goes quiet does not keep a stale window forever.

> Because the window is measured from **the event's own `timestamp`** (not the
> wall clock at evaluation time), the behavior is replay-safe and deterministic —
> the same event stream always produces the same signals, which is what lets
> `MemoryHotState` back the test suite.

## Rule 1 — Credential brute-force / password spray

`BruteForceRule` (`RULE_BRUTE_FORCE`)

- **Inputs:** an `http.request`-style event where `action.is_success` is `false`
  **and** (`status_code == 401` **or** the endpoint matches any of
  `login`, `auth`, `token`, `session`). Anything else is ignored — a failed
  request that is not an auth failure does not count.
- **Keying:** `bf:ip:<source.ip>` (falls back to `unknown`).
- **Window / threshold:** `window_ms = 60_000` (60 s), `threshold = 10`.
  Fires when `record_hit` returns a count `>= 10` inside the 60 s window.
- **Severity / risk weight:** `High` / `35`.
- **Expected outcome:** a `High` signal *"Detected credential brute-force attack
  from IP <ip>: <n> failed authentication attempts within 60s"*; the incident
  opens at risk ≥ 35. Pinned by `test_phase2_engine.py::test_01` (12 failed
  logins → incident, `risk_score >= 35`, rule name present).

## Rule 2 — Rapid API / directory enumeration

`RapidApiEnumerationRule` (`RULE_API_ENUMERATION`)

- **Inputs:** any event with `action.status_code == 404`. Two independent keys are
  tracked per source IP:
  - `enum_404:ip:<ip>` — total 404s in window (`record_hit`).
  - `enum_paths:ip:<ip>` — *distinct* 404 endpoints in window
    (`record_distinct`, one TTL of `window_ms / 1000` seconds).
- **Window / thresholds:** `window_ms = 60_000`, `count_threshold = 20`,
  `distinct_threshold = 25`. Fires when **either** total 404s `>= 20` **or**
  distinct endpoints `>= 25` inside the window.
- **Severity / risk weight:** `Medium` / `25`.
- **Expected outcome:** *"Detected rapid API enumeration from IP <ip>: <n> 404
  errors across <m> distinct endpoints in 60s"*. Pinned by
  `test_phase2_engine.py::test_02` (25 distinct 404 probes → incident).

## Rule 3 — Unauthorized access burst (401/403)

`UnauthorizedBurstRule` (`RULE_UNAUTHORIZED_BURST`)

- **Inputs:** any event with `status_code == 401` **or** `403`. This is the
  "privilege probing / token forgery" counterpart to rule 1 (rule 1 is
  *failed authentication*; rule 3 is *repeatedly rejected access*).
- **Keying:** `unauth:ip:<ip>`.
- **Window / threshold:** `window_ms = 60_000`, `threshold = 15`. Fires at
  `>= 15` unauthorized responses inside 60 s.
- **Severity / risk weight:** `High` / `30`.
- **Expected outcome:** *"Detected abnormal burst of unauthorized (401/403)
  requests from IP <ip>: <n> occurrences within 60s"*.

## Rule 4 — Mass data scraping / export burst

`MassDataScrapingRule` (`RULE_MASS_DATA_SCRAPING`)

- **Inputs:** `GET` requests whose endpoint contains any of `/export`,
  `/records`, `/download`, `/customers`, `/dump`. Non-GET or other paths are
  ignored.
- **Keying:** `scrape:ip:<ip>`.
- **Window / threshold:** `window_ms = 60_000`, `threshold = 25`. Fires at
  `>= 25` data-endpoint requests inside 60 s.
- **Severity / risk weight:** `High` / `30`.
- **Expected outcome:** *"Detected mass data scraping from IP <ip>: <n> data
  query requests in 60s"*.

## Rule 5 — Suspicious container / kernel execution (eBPF)

`KernelAnomalyRule` (`RULE_KERNEL_ANOMALY`)

This rule is **stateless** (it does not read hot state). It fires on a
*single* event that looks like a shell or unapproved utility running inside a
container, captured by an eBPF/runtime sensor.

- **Inputs:** the event is treated as a kernel event when its sensor type is
  `Tetragon` / `Falco` / `System` / `NativeSensor`, **or** its `event_type`
  contains `process_exec`, `falco`, `tetragon`, or `kernel.execve`.
- **Trigger:** it fires when the process name / command / raw event type matches
  one of the suspicious binaries — `/bin/sh`, `/bin/bash`, `sh`, `bash`, `nc`,
  `ncat`, `netcat`, `curl`, `wget`, `socat`, `sudo` — **or** the event is
  already `Critical` severity.
- **Severity / risk weight:** `Critical` / `50` (the highest of any rule).
- **Expected outcome:** *"Kernel/eBPF runtime alarm: unauthorized binary or
  shell execution detected in app container '<app>' (binary: '<b>', sensor:
  <type>)"*. Pinned by `test_phase2_engine.py::test_03` (a Tetragon
  `process_exec` of `/bin/bash` → `Critical` incident, `risk_score >= 50`).

> Note the binary list is shared with the **adapter**-side classification in
> `crates/sensors/src/tetragon.rs` (`classify_binary`): a shell inside a
> container is the critical case there too. Keep the two lists consistent.

## Rule 6 — Administrative privilege creep / probe

`PrivilegeCreepRule` (`RULE_PRIVILEGE_CREEP`)

Also **stateless** — one suspicious event is enough.

- **Inputs:** any event whose endpoint contains `/admin`, `/root`, or
  `/system/keys`.
- **Trigger:** the acting role is **not** `admin` (an unauthenticated event has
  no `actor.role`, so it counts as not-admin by default), **and** the status is
  `401` / `403` / `200`. A `200` here means a non-admin actually *reached* an
  admin route — the most concerning case.
- **Severity / risk weight:** `High` / `35`.
- **Expected outcome:** *"Unauthorized actor '<user|unauthenticated>' from IP
  <ip> probed sensitive admin endpoint (status: <code>)"*.

## Risk accumulation & severity escalation

Signals are not independent alarms — the engine folds each into the target
entity's risk score (`incident.rs`, `Incident::add_signal`). The score is the
sum of every signal's `risk_weight` with a 1-hour TTL, and the incident
severity is re-derived from it:

| Accumulated `risk_score` | Incident severity |
|--------------------------|-------------------|
| `>= 100` | `Critical` |
| `>= 50` | `High` |
| `>= 25` | `Medium` |
| else | `Low` |

So a `Medium`-severity enumeration (rule 2, weight 25) that repeats alongside a
`High` brute-force (rule 1, weight 35) crosses 50 and escalates the incident to
`High`, and a few more pushes past 100 to `Critical` — this is the "Medium →
High → Critical" escalation called out in
`test_phase2_engine.py`'s docstring (item 4).

## Keeping this page in sync

- Every threshold, window, key prefix, binary list, and status-code check above
  is a literal in `crates/engine/src/rules/mod.rs`. When any of them changes,
  update the matching rule section and the `Default` impl in the same commit.
- The rule **names** (the `name()` strings) are what the Python integration
  tests assert on, so a rename requires a matching edit in
  `tests/test_phase2_engine.py`.
- The escalation ladder lives in `crates/engine/src/incident.rs`
  (`add_signal`), not in a rule — update the table there changes.

Run the engine tests after touching any of these files:

```bash
cargo test -p security-control-plane-engine
# Behavioral pinning (needs the control plane running on :8080):
python tests/test_phase2_engine.py
```
