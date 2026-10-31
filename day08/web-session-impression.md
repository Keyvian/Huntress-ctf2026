# 🌐 Session Impression

| | |
|---|---|
| **Day** | 08 (released on GM day 21) |
| **Lane** | 🌐 Web Exploitation |
| **Challenge ID** | `web-exploitation-day-08-session-impression` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/web/webrun.py`](../solvers/web/webrun.py) (`solve_session`) |

## Prompt
> First impressions matter. Plant your session on the welcome mat, then stroll in wearing somebody else's credentials.

## TL;DR
A **session fixation**. The app lets you choose the session id (it blindly sets a cookie to whatever you pass), and the victim's authenticated session already uses a known id disclosed in the clues. Plant that id, then visit the status route with that cookie to inherit the victim's login.

## Artifact
No file; live target, proof `proof_<32 hex>`, answer id `proof-1` (mastery `proof-1..N`). Framework **Laravel** (skin "Resume Room", no openapi). `GET /api/clues`:

```json
{"feature_route": "/action-<hex>", "secondary_route": "/status-<hex>", "session_hint": "<12 hex>"}
```

`session_hint` is the victim's session id.

## Solution
1. `GET <feature_route>?sid=<session_hint>` — the parameter is literally `sid`. The route 400s `session_id_required` without it, and with it blindly sets cookie `arena_session=<value>` (the fixation flaw).
2. `GET <secondary_route>` reusing that cookie jar. Because the cookie now equals the victim's session id, the request inherits the victim's authenticated login and returns the proof.

`secondary_route` on its own (without the planted cookie) returns `403 authenticated_login_required`.

## Time Trial & Mastery
Played untimed via `run_for_time:false` (single omits it). Mastery bundles **3 sets** (the mastery set count steps up to 3 here), types possibly mixed. `detect()` keys on the unique `session_hint` clue. Route names, sid parameter, and hint are read live.

## Lessons / gotchas
- The flaw is that the server accepts a *client-chosen* session id and that the victim's id is leaked — the two together make fixation trivial; neither alone is enough.
- Keep the same `requests.Session` cookie jar across the plant and the status fetch.
- Shared live-target and proof mechanics: [lane overview](../lanes/web.md).
