# 🌐 Administratively Speaking

| | |
|---|---|
| **Day** | 05 (released on GM day 20) |
| **Lane** | 🌐 Web Exploitation |
| **Challenge ID** | `web-exploitation-day-05-administratively-speaking` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/web/webrun.py`](../solvers/web/webrun.py) (`solve_admin`) |

## Prompt
> There's a staff-only door with no lock on it — just a sign. Walk through like you own the place and prove the bouncer never existed.

## TL;DR
**Broken access control.** A "staff-only" feature route has no server-side authorization at all — just a label saying it's restricted. Requesting it directly as the ordinary analyst returns the proof. This is the first challenge to use the `/api/clues` discovery endpoint that most later web challenges share.

## Artifact
No file; live target, proof `proof_<32 hex>`, answer id `proof-1` (mastery `proof-1..N`). Framework **Django** (skin "Django Dispatch"). The homepage links `GET /api/clues`, which returns JSON:

```json
{"framework": "...", "feature_route": "/dispatch-<hex>", "current_role": "analyst"}
```

## Solution
1. `GET /api/clues` → read `feature_route` (a randomized `/dispatch-<hex>` path) and `current_role` (`analyst`, i.e. not staff).
2. `GET <feature_route>` directly. There is no role check, cookie gate, or parameter required — the "lock" is only a sign:

```json
{"ok": true, "effect": "framework_authorization_bypassed", "evidence": "proof_…"}
```

The proof is the `evidence` field. No header, cookie, or role parameter is needed; the authorization code simply doesn't exist on that route.

## Time Trial & Mastery
Played untimed via `run_for_time:false` (single omits it). Mastery bundles **2 sets**, types possibly mixed. The feature route is randomized per attempt but always named in `/api/clues`, so the solver reads it fresh.

## Lessons / gotchas
- `/api/clues` is the lane's recon backbone from here on: the solver's `detect()` fetches it first and branches on its fields. Several later challenges share the bare `{feature_route}` or `{feature_route, secondary_route}` clue shape, so they can only be told apart by live probing — see [the lane overview](../lanes/web.md).
- In particular this challenge looks identical to [Day 11 (SSTI)](../day11/web-template-temper.md) at the clue level (both have `feature_route`, no `secondary_route`); the solver disambiguates by probing `?template={{7*7}}` first, and only falls back to "admin" when nothing evaluates.
