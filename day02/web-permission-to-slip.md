# 🌐 Permission to Slip

| | |
|---|---|
| **Day** | 02 (released on GM day 19) |
| **Lane** | 🌐 Web Exploitation |
| **Challenge ID** | `web-exploitation-day-02-idor` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/web/webrun.py`](../solvers/web/webrun.py) (`solve_idor`), legacy [`solvers/web/web02_idor.py`](../solvers/web/web02_idor.py) |

## Prompt
> Your neighbor's records are none of your business. Pity the object API never got that memo — see if you can slip into somebody else's row.

## TL;DR
An **IDOR** (insecure direct object reference). Loading the homepage signs you in as a fixed user; an activity feed leaks a record id that belongs to *another* workspace; the object API hands that record over without checking ownership. The proof is inside the foreign record.

## Artifact
No file. A live target per attempt; proof is `proof_<32 hex>`, answer id `proof-1` (mastery `proof-1..N`). Skins observed: "Permission to Slip", "Pocket SOC", "Incident Picnic".

- `GET /` sets a session cookie and shows "Signed in as *<name>*".
- The homepage links an activity/history feed under `/api/…` (e.g. `/api/history`, `/api/events`).
- Case/record objects are read via a JSON API, e.g. `/api/briefs/<id>` or `/api/incidents/<id>`.

## Solution
1. `GET /` to obtain the session cookie.
2. Fetch the activity feed; it lists events, at least one referencing a **foreign-owned** `case_id` (owner ≠ current user, often tagged "outside your workspace").
3. `GET` that record through the case API (`/api/briefs/<id>` etc.). The server returns it despite the ownership mismatch — the IDOR.
4. The proof is in the record's `note` / `summary` field.

The flaw is pure missing authorization on an object lookup: the endpoint trusts the id in the URL and never confirms the caller owns the object.

## Time Trial & Mastery
Played untimed via `run_for_time:false` on `/time_trial` and `/mastery`; single omits it. Mastery bundles **2 sets**, possibly of mixed types, so the solver re-detects per target. The feed/record route names are randomized per attempt, so the solver discovers them from the homepage links rather than hard-coding paths.

## Lessons / gotchas
- Discover endpoint names from the live homepage every time — they are randomized per attempt.
- "Foreign" is identified by the owner field in the feed, not by guessing ids; read the feed and pick the entry that isn't yours.
- Shared live-target and proof mechanics are described in [the lane overview](../lanes/web.md).
