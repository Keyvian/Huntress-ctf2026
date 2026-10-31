# 🌐 Internal Affairs

| | |
|---|---|
| **Day** | 27 (released on GM day 29) |
| **Lane** | 🌐 Web Exploitation |
| **Challenge ID** | `web-exploitation-day-27-internal-affairs` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/web/webrun.py`](../solvers/web/webrun.py) (`solve_internalaffairs`) |

## Prompt
> Two service boundaries, one hallway. Use the public fetch to knock on the internal door, then borrow somebody else's records on the way out.

## TL;DR
An **SSRF chained into object-level authorization**. A public route is a loopback-only fetcher; the internal case service returns any case by `?id=` with no object authz. SSRF the fetcher at the internal service with a *foreign* case id.

## Artifact
No file; live target, proof `proof_<32 hex>`, answer id `proof-1` (mastery `proof-1..N`). Framework **Kotlin Ktor**. `GET /api/clues`:

```json
{"framework": "Ktor", "feature_route": "/submit-<hex>",
 "case_directory_route": "/api/cases", "topology_route": "/api/topology",
 "current_role": "analyst", "service_pattern": "server-side case fetch"}
```

- `GET /api/cases` → `{cases:[{id:<ours>,owner:"analyst"},{id:<foreign>,owner:"executive"}]}`.
- `GET /api/topology` → `{case_service:"http://127.0.0.1:8080/status-<hex>","network":"loopback"}`.

## Solution
`feature_route` is a server-side fetcher: `GET ?target=<url>` (parameter `target`; none → `400 target_required`; a non-loopback target → `400 loopback_http_target_required`; the internal base with no id → `404 not_found`). The internal service returns a case by `?id=` with no object-level authz. Chain them:

```
GET <feature_route>?target=http://127.0.0.1:8080/status-<hex>?id=<foreign_case_id>
→ {"ok":true,"effect":"ssrf_then_object_authorization","evidence":"proof_…"}
```

The winning `target` is the **full internal URL including `?id=<foreign>`**; `requests` percent-encodes the inner `?`/`=` in the parameter value and the server decodes it fine. Path forms (`/status-<hex>/<id>`) → 404. `solve_internalaffairs` discovers the `target` parameter name from the 400 body, reads `case_service` from topology and the foreign (owner ≠ current_role) id from cases, then SSRFs `<case_service>?id=<foreign>` (sweeping `id`/`case`/`case_id` and loopback hosts as fallback).

## Time Trial & Mastery
Played untimed via `run_for_time:false` (single omits it). Mastery bundles **5 sets**, types possibly mixed. `detect()` keys on the unique `case_directory_route` + `topology_route` and runs it **before** the feature-route block (Day 27 has a `feature_route` but no `secondary_route`, else it would misdetect as admin).

## Lessons / gotchas
- Two bugs stacked: the fetcher reaches the internal service (SSRF), and the internal service has no per-object authz (IDOR). You need both.
- Put the whole internal URL — including `?id=<foreign>` — inside the `target` value; let the client URL-encode the inner query.
- Extends the [Day 15 (SSRF)](../day15/web-fetch-quest.md) fetcher pattern. Shared live-target mechanics: [lane overview](../lanes/web.md).
