# 🌐 Forged With Care

| | |
|---|---|
| **Day** | 09 (released on GM day 22) |
| **Lane** | 🌐 Web Exploitation |
| **Challenge ID** | `web-exploitation-day-09-forged-with-care` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/web/webrun.py`](../solvers/web/webrun.py) (`solve_csrf`) |

## Prompt
> The browser obeys whoever asks nicely — even strangers. Forge one careful request and make the app change its mind while signed in as someone else.

## TL;DR
A **CSRF**. The preferences form carries a `csrf_token`, but the token is never validated; the only thing gating the sensitive change is whether the request looks cross-site. Sending the state-changing request with `Sec-Fetch-Site: cross-site` (and a non-default destination) flips the change and reveals the proof.

## Artifact
No file; live target, proof `proof_<32 hex>`, answer id `proof-1` (mastery `proof-1..N`). Framework **ASP.NET Core MVC** (skin "Notification Nook"). `GET /api/clues`:

```json
{"feature_route": "/submit-<hex>", "preferences_route": "/preferences", "browser_session": "established"}
```

`preferences_route` serves a **GET** form (action = `feature_route`) with a `destination` `<select>` (default `daily` plus one external-mailbox option) and a hidden `csrf_token`. Loading any page sets the victim cookie `arena_session` (its value even equals the token).

## Solution
1. `GET <preferences_route>`; parse the form `action`, the `<select>` name, its option values, and the "Current destination".
2. Pick the option that is neither the current value nor `daily` (the external mailbox).
3. Fire the state change as if cross-site:

```
GET <feature_route>?destination=<external option>
Sec-Fetch-Site: cross-site
```

The `csrf_token` is **not** checked; `Sec-Fetch-Site: cross-site` alone makes the server treat the request as genuinely cross-site and sets `changed_across_sites:true`. (A cross-site `Origin`/`Referer` help too, but the fetch-metadata header suffices.)
4. `GET /api/preferences` — the proof is the `evidence` field there.

## Time Trial & Mastery
Played untimed via `run_for_time:false` (single omits it). Mastery bundles **3 sets**, types possibly mixed. `detect()` keys on `preferences_route` / `browser_session`. The form is parsed live, so randomized option values don't matter.

## Lessons / gotchas
- The decoy is the `csrf_token`: it exists but is ignored. The real gate is the cross-site *appearance* of the request, which `Sec-Fetch-Site: cross-site` satisfies without a browser.
- Must pick a destination different from the current/default one, or nothing "changes."
- The csrf clue-check must run before the generic `admin` fallback in `detect()` (day-09 carries a `feature_route` too) — see [lane overview](../lanes/web.md).
