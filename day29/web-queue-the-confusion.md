# 🌐 Queue the Confusion

| | |
|---|---|
| **Day** | 29 (released on GM day 30) |
| **Lane** | 🌐 Web Exploitation |
| **Challenge ID** | `web-exploitation-day-29-queue-the-confusion` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/web/webrun.py`](../solvers/web/webrun.py) (`solve_queuebind`) |

## Prompt
> Your job went into the queue with your name on it. Loosen the binding and watch somebody else's outcome come out wearing your stamp.

## TL;DR
A **queue owner-binding bypass**. You queue a job with a client-supplied `owner` and the server never checks that the caller may act as that owner. Queue a job as the restricted owner, then read its outcome.

## Artifact
No file; live target, proof `proof_<32 hex>`, answer id `proof-1` (mastery `proof-1..N`). Framework **Pyramid/Python** (skin "Job Post"). `GET /api/clues`:

```json
{"framework": "Pyramid", "feature_route": "/process-<hex>", "secondary_route": "/audit-<hex>",
 "owner_directory_route": "/api/owners", "current_role": "analyst"}
```

`GET /api/owners` → `{"caller":"analyst","restricted_owner":"executive"}`.

## Solution
1. `feature_route` GET → `405 {"error":"post_required","request_fields":["owner"]}`. `POST {"owner":<v>}` queues a job → `201 {"ok":true,"id":"<n>","queued_owner":<v>}` with **no check** that the caller may queue as that owner.
2. `secondary_route` GET → `400 {"error":"job_id_required","query_parameter":"id"}`; `GET secondary_route?id=<n>` reads the job's outcome.

Queue as the restricted owner, then read it:

```
POST <feature_route> {"owner": "executive"}        → id=<n>
GET  <secondary_route>?id=<n>
→ {"ok":true,"effect":"queue_owner_binding_bypassed","evidence":"proof_…"}
```

`owner:analyst` or a missing owner → the job reads `403 job_not_authorized`; `owner` as a list/object → also 403. It must be the plain `restricted_owner` **string**. `solve_queuebind` reads `restricted_owner` (directory value ≠ caller), discovers the owner field name (`request_fields[0]`) and id query-param (`query_parameter`), POSTs, then reads the secondary route.

## Time Trial & Mastery
Played untimed via `run_for_time:false` (single omits it). Mastery bundles **6 sets** (the mastery set count steps up to 6 here), types possibly mixed. `detect()` keys on the unique `owner_directory_route`. Day 29 has **both** `feature_route` and `secondary_route` (the secondary 400s `job_id_required` on a bare GET), so this check runs **before** the feat+sec block, or it would fall through to admin.

## Lessons / gotchas
- The owner must be the plain string from the directory — not a list/object, not your own name.
- It's a two-step flow: POST to queue, GET the audit route by the returned id; the proof is on the read side.
- Shared live-target mechanics and the detection ordering: [lane overview](../lanes/web.md).
