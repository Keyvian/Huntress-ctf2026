# 🌐 Trust the Webhook

| | |
|---|---|
| **Day** | 19 (released on GM day 26) |
| **Lane** | 🌐 Web Exploitation |
| **Challenge ID** | `web-exploitation-day-19-trust-the-webhook` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/web/webrun.py`](../solvers/web/webrun.py) (`solve_webhook`) |

## Prompt
> The app believes every event it's told about. Tell it a convincing enough story and watch it act on your forged news.

## TL;DR
A **forged-webhook trust** flaw. The receiver has **no signature verification at all**; it only wants a complete, well-formed event record. POST a superset event body carrying the clued `event_type` and `owner_scope` and it acts on your forged event.

## Artifact
No file; live target, proof `proof_<32 hex>`, answer id `proof-1` (mastery `proof-1..N`). Framework **Starlette**. `GET /api/clues`:

```json
{"framework": "Starlette", "feature_route": "/dispatch-<hex>", "current_role": "analyst",
 "event_type": "case.promoted", "owner_scope": "executive"}
```

The unique clue keys `event_type` + `owner_scope` (both randomized per variant) are the event type/scope to forge.

## Solution
`feature_route` GET = `405 post_required`. The POST handler is a webhook receiver with **no crypto gate** — this was confirmed by brute force: 1344 HMAC combinations (12 header names × empty/weak/context secrets × sha256/sha1 × hex/base64 × prefix) all returned the same flat `{"error":"webhook_rejected"}`, as did malformed JSON, every signature header, every `source`/`verified`/`trusted` field, and a JWT `alg:none`. The 403 is a generic try/except catch-all: it only accepts a **complete, well-formed event record**.

A bare `{event_type, owner_scope}` is rejected; a flat **superset** body succeeds:

- `event_type` / `type` / `event` / `name` = the type value; `action` = `type.split(".")[-1]`
- `owner_scope` / `scope` / `new_scope` / `owner` / `access` = the scope value
- `subject` / `user` / `username` / `target` = `current_role`
- `id` / `event_id` / `delivery_id` / `case_id` …; plus `actor` / `source` / `timestamp` / `ts`

→ `200 {"effect":"forged_event_consumed","evidence":"proof_…"}`. The exact minimal field set couldn't be isolated (the single target flips to `{"state":"completed"}` right after the winning submit), so `solve_webhook` just sprays the superset, like the [mass-assignment](../day13/web-posted-too-much.md) solver.

## Time Trial & Mastery
Played untimed via `run_for_time:false` (single omits it). Mastery bundles **4 sets**, types possibly mixed. `detect()` keys on the unique `event_type` + `owner_scope` and runs this check **before** the feature-route block (Day 19 has a `feature_route` but no `secondary_route`, so it would otherwise misdetect as admin/SSTI).

## Lessons / gotchas
- The misdirection is the signature: the prompt invites crypto, but there is none to defeat — the gate is just "well-formed event."
- When the real field set is unknowable because the target self-completes on success, spraying a superset is the pragmatic win.
- Shared live-target and proof mechanics: [lane overview](../lanes/web.md).
