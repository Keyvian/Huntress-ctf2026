# 🌐 Full Stack Incident

| | |
|---|---|
| **Day** | 31 (released on GM day 31) |
| **Lane** | 🌐 Web Exploitation |
| **Challenge ID** | `web-exploitation-day-31-full-stack-incident` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/web/webrun.py`](../solvers/web/webrun.py) (`solve_fullstack`, per-target `detect()` + dispatch) |

## Prompt
> Reconstruct the unsigned fetch-to-worker incident from the request log. Follow the exposed service routes to reproduce it, inspect the resulting evidence, then submit a detector and repair that block the attack while preserving signed status checks.

## TL;DR
The final challenge: not one bug but a **multi-stage reproduce-then-remediate chain**. Replay an unsigned internal fetch from the request log, drive it through a worker dispatch to execute, inspect the evidence, then POST a detector + repair derived from the event log schema. Mastery also mixes types.

## Artifact
No file; live target, proof `proof_<32 hex>`, answer id `proof-1` (mastery `proof-1..N`). Framework **Actix Web/Rust**. `GET /api/clues`:

```json
{"feature_route": "/dispatch-<hex>", "secondary_route": "/audit-<hex>", "final_route": "/worker-<hex>",
 "evidence_route": "/api/evidence", "response_route": "/api/response", "request_log_route": "/api/requests",
 "fetch_query_field": "target", "event_json_field": "token", "worker_query_field": "command"}
```

The unique clue keys `final_route` + `request_log_route` identify this type.

## Solution
A six-step chain:

1. `GET request_log_route` → find the queued, unsigned internal fetch target (`signed:false, outcome:queued` → a short hex id, `<hex>`).
2. `GET feature_route?target=<id>` → `fetch_event_created`.
3. `POST secondary_route {"token":<id>}` → `worker_dispatched`, returning `available_commands:["status","cat <resource>"]` and `resources:["objective"]`.
4. `GET final_route?command=status` (benign/signed) then `GET final_route?command=cat objective` — the unsigned worker dispatch that executes.
5. `GET evidence_route` → incident reproduced; returns the event log plus `regression_goal` and a `response_schema`:

```json
{"detector": {"kind": "string", "signed": "boolean"},
 "repair": {"block_internal_fetch": "boolean", "require_signed_event": "boolean", "worker_allowlist": ["string"]}}
```

6. `POST response_route` with the analysis, built data-driven from the event log:

```json
{"detector": {"kind": "worker.dispatch", "signed": false},
 "repair": {"block_internal_fetch": true, "require_signed_event": true, "worker_allowlist": ["status"]}}
→ {"effect":"incident_detected_and_remediated","evidence":"proof_…","regressions":{…all true}}
```

`detector.kind` = the kind of the `signed:false` event that executed; `worker_allowlist` = the commands of `signed:true` events (so `status` is allowed, `cat objective` is blocked). `solve_fullstack` reads the field names from the clues (`fetch_query_field`, `event_json_field`, `worker_query_field`) and the schema from the evidence route, so it adapts to randomized route/field names.

## Time Trial & Mastery
Played untimed via `run_for_time:false` (single omits it). Mastery bundles **8 sets** (the largest in the lane) and MIXES types — e.g. an 8-target bundle = 7 other catalog types + 1 full-stack. The per-target `detect()` + dispatch handles it: `detect()` keys on the unique `final_route` + `request_log_route` **first** (Day 31 carries feat+sec, but its secondary GET returns `event_not_verified`, which matches no feat+sec branch). Confirmed single/Time Trial CORRECT and Mastery 8/8 CORRECT.

## Lessons / gotchas
- This is a *reproduce then remediate* task: you must first make the attack happen (steps 1–4), then describe how to detect and fix it (step 6). A proof is only issued once the remediation passes all `regressions`.
- Build the detector/repair from the data, not from constants: `detector.kind` from the executed unsigned event, `worker_allowlist` from the signed commands — "preserve signed status checks" means `status` stays allowed.
- The clue fields name every randomized route and body field, so read them rather than hard-coding. Shared live-target mechanics and the full type catalog: [lane overview](../lanes/web.md).
