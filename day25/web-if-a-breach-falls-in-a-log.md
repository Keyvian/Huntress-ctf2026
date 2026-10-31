# 🌐 If a Breach Falls in a Log

| | |
|---|---|
| **Day** | 25 (released on GM day 28) |
| **Lane** | 🌐 Web Exploitation |
| **Challenge ID** | `web-exploitation-day-25-if-a-breach-falls-in-a-log` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/web/webrun.py`](../solvers/web/webrun.py) (`solve_logaudit`) |

## Prompt
> You broke in, and nobody wrote it down. Find the decisive moment the logs missed — if a breach falls in the forest, did it make a sound?

## TL;DR
A **log/audit discrepancy**. A privileged `protected_export` action is logged, but the public audit feed masks it as an innocuous `page_view`. Perform the export, then submit the audit comparison stating the decisive event (`protected_export`) is missing/observed-as `page_view` to surface the proof.

## Artifact
No file; live target, proof `proof_<32 hex>`, answer id `proof-1` (mastery `proof-1..N`). Framework **Slim/PHP**. `GET /api/clues`:

```json
{"framework": "Slim", "feature_route": "/process-<hex>", "secondary_route": "/status-<hex>", "current_role": "analyst"}
```

Generic feat+sec shape (same as Days 12/13/15/21). `GET secondary_route` returns the public audit feed (all entries `page_view`) plus a schema `report:{method:"POST", fields:["export_id","missing_event","observed_event"]}`.

## Solution
1. `POST <feature_route>` (GET → `405 post_required`) performs a privileged export:

```json
{"ok": true, "export": "completed", "export_id": "<24 hex>", "operation": "protected_export"}
```

The export *is* logged, but `GET secondary_route`'s public feed shows our `export_id` as a `page_view` — the breach "falls in a log" unheard.
2. Submit the audit comparison naming the mismatch:

```
POST <secondary_route> {"export_id": <the logged export>, "missing_event": "protected_export", "observed_event": "page_view"}
→ {"ok":true,"effect":"decisive_security_event_missing","evidence":"proof_…"}
```

Swapping missing/observed → `422 audit_comparison_rejected`; the `export_id` must be a genuine `protected_export`, so the `/process` POST must come first. `solve_logaudit` reads `report.fields` + the masked label from status, POSTs `/process` for a real export id, then POSTs the comparison mapping by field-name substring.

## Time Trial & Mastery
Played untimed via `run_for_time:false` (single omits it). Mastery bundles **5 sets**, types possibly mixed. Day 25 shares the feat+sec shape, so `detect()`'s secondary-route probe checks for `missing_event` / `observed_event` or `page_view` + `export_id` in the body **first** (before the credit/ssrf/massassign branches).

## Lessons / gotchas
- The export id must be a real `protected_export` you created — the comparison is validated against an actual logged event.
- Don't swap the `missing_event`/`observed_event` fields; the direction matters (decisive event missing, benign event observed).
- Shared live-target mechanics and the feat+sec disambiguation order: [lane overview](../lanes/web.md).
