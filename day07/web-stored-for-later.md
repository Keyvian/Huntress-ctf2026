# 🌐 Stored for Later

| | |
|---|---|
| **Day** | 07 (released on GM day 21) |
| **Lane** | 🌐 Web Exploitation |
| **Challenge ID** | `web-exploitation-day-07-stored-xss` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/web/webrun.py`](../solvers/web/webrun.py) (`solve_stored`) |

## Prompt
> Leave a little present in the guestbook. It only goes off when the reviewer stops by — good things come to those who wait.

## TL;DR
A **stored XSS**. You post a message whose raw HTML is rendered in a detail view; a reviewer bot opens it in an authenticated browser within ~15 s and actually executes the payload. The payload fetches a moderator-only resource and writes the result back to the message's own receipt route, where the proof then appears.

## Artifact
No file; live target, proof `proof_<32 hex>`, answer id `proof-1` (mastery `proof-1..N`). Framework **FastAPI** (has `/openapi.json`; skins "Feedback Loop", postcards). `GET /api/clues`:

```json
{"feature_route": "/messages|/postcards",
 "moderator_data_route": "/<hex>",
 "receipt_route_template": "/api/<thing>/{id}/evidence-<hex>"}
```

The `moderator_data_route` holds the proof but is `403 moderator only` for us. The `message` field in `POST /api/<thing>` is the raw-HTML sink rendered in `/<thing>/{id}`.

## Solution
1. `POST /api/<thing>` with `{"message": "<payload>"}`. The response gives `{id, url}`. The API base is `receipt_route_template.split("{")[0]` (e.g. `/api/postcards`, not always `/api/messages`).
2. The payload is HTML/JS that runs in the reviewer's authenticated context:
   - `fetch` the `moderator_data_route` (proof is accessible *to the reviewer*),
   - read this message's own id from `location.pathname`,
   - `POST` the fetched text to the per-message evidence route (the `receipt_route_template` with `{id}` substituted) as `{"evidence": t}`.
3. A reviewer bot opens `/<thing>-review/{id}` within ~15 s and executes the `<img src=x onerror=...>`-style payload.
4. `GET <url>` — the proof is now the stored receipt.

The attack chains stored XSS with the reviewer's privileges: we can't read the moderator route, but the bot can, and our injected script exfiltrates it to a route we *can* read.

## Time Trial & Mastery
Played untimed via `run_for_time:false` (single omits it). Mastery bundles **2 sets**, types possibly mixed. `detect()` keys on `moderator_data_route` / `receipt_route_template`. The ~15 s reviewer delay is the one real wait in the lane; untimed play absorbs it with no issue.

## Lessons / gotchas
- Compute the API base from `receipt_route_template`, not from the human-facing `feature_route` — the two prefixes differ across skins.
- The proof is reachable only via the bot's session; the payload must both read the moderator resource and write it somewhere we can poll.
- Shared live-target and proof mechanics: [lane overview](../lanes/web.md).
