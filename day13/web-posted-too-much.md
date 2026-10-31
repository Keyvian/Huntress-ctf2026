# 🌐 Posted Too Much

| | |
|---|---|
| **Day** | 13 (released on GM day 23) |
| **Lane** | 🌐 Web Exploitation |
| **Challenge ID** | `web-exploitation-day-13-posted-too-much` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/web/webrun.py`](../solvers/web/webrun.py) (`solve_massassign`) |

## Prompt
> The form only asked for your name. But the API binds whatever you hand it — so hand it a promotion.

## TL;DR
A **mass assignment / over-posting**. The profile endpoint binds every field in the JSON body blindly, including a privileged property the form never shows. Over-post that property to flip your account to admin, then read the audit route for the proof.

## Artifact
No file; live target, proof `proof_<32 hex>`, answer id `proof-1` (mastery `proof-1..N`). Framework **NestJS** (skin "Profile Binder"). `GET /api/clues`:

```json
{"framework": "NestJS", "feature_route": "/inspect-<hex>", "secondary_route": "/audit-<hex>", "current_role": "..."}
```

`feature_route` GET = `405 post_required`; `secondary_route` (audit) GET = `403 administrator_required` until the account is elevated.

## Solution
The privileged property name is randomized per variant (`role`, `is_admin`, `admin`, `clearance`, `level`, …), so post a **superset** of likely names in one body:

1. `POST <feature_route>` with a profile JSON containing `{"role":"administrator","is_admin":true,"admin":true,"clearance":"admin","level":...}` etc. The server binds them all; the account flips to admin and the change **persists** for the session.
2. `GET <secondary_route>` → `{"effect":"bound_privileged_property","evidence":"proof_…"}`.

Posting the superset is robust to the randomized field name. Note that once elevated, a re-POST keeps the account elevated, so you can't isolate *which* field was the real one on an already-elevated target — the superset sidesteps that.

## Time Trial & Mastery
Played untimed via `run_for_time:false` (single omits it). Mastery bundles **3 sets**, types possibly mixed. Shares the `{feature_route, secondary_route}` shape with [Day 12](../day12/web-ask-again-later.md); `detect()` tells them apart by the secondary route's GET (403 `administrator_required` ⇒ mass-assignment).

## Lessons / gotchas
- Spray the superset of privileged field names rather than guessing the one true name — same tactic reused by the later deserialization/webhook challenges.
- The elevation persists; don't expect to probe field names one at a time on a live target.
- Shared live-target and proof mechanics: [lane overview](../lanes/web.md).
