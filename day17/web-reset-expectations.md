# 🌐 Reset Expectations

| | |
|---|---|
| **Day** | 17 (released on GM day 25) |
| **Lane** | 🌐 Web Exploitation |
| **Challenge ID** | `web-exploitation-day-17-reset-expectations` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/web/webrun.py`](../solvers/web/webrun.py) (`solve_resettoken`) |

## Prompt
> Forgot your password? This recovery flow forgot its manners. Walk the reset process sideways and wake up in somebody else's account.

## TL;DR
A **reset token not bound to its account**. You can request a recovery token for your own self-service account, then redeem that token against a *different* (privileged) account — the redeem step never checks that the token was issued for that account.

## Artifact
No file; live target, proof `proof_<32 hex>`, answer id `proof-1` (mastery `proof-1..N`). Framework **Symfony**. `GET /api/clues`:

```json
{"framework": "Symfony", "feature_route": "/submit-<hex>", "secondary_route": "/result-<hex>",
 "recovery_guide_route": "/api/recovery", "current_role": "..."}
```

`GET /api/recovery`:

```json
{"request_route": "...", "redeem_route": "...",
 "account_parameter": "account_id", "token_parameter": "token",
 "accounts": [{"id": <self>, "self_service": true}, {"id": <exec>, "self_service": false}]}
```

## Solution
1. `GET <request_route>?account_id=<self>` → `{"ok":true,"token":"<12 hex>"}`. The token is deterministic per account (HMAC-like, **not** a plain hash of the id, so it can't be precomputed). Requesting for the exec account directly → `403 self_service_only`.
2. The flaw: the redeem route does **not** bind the token to the account.

```
GET <redeem_route>?account_id=<exec>&token=<self's token>
→ {"ok":true,"effect":"synthetic_account_recovery","evidence":"proof_…"}
```

Redeeming against your own id only yields `analyst_recovery_verified`; a bogus token → `403 invalid_recovery_token`. The solver reads the guide, requests a token for a `self_service:true` account, and redeems it against each `self_service:false` account.

## Time Trial & Mastery
Played untimed via `run_for_time:false` (single omits it). Mastery bundles **4 sets**, types possibly mixed. `detect()` keys on the unique `recovery_guide_route`, and this check runs **before** the feature/secondary disambiguation block (Day 17 carries both routes).

## Lessons / gotchas
- You can't forge the token (it's keyed), but you don't need to — issue a legitimate one for an account you control and reuse it elsewhere.
- Read the accounts list to find a `self_service:true` source and the `self_service:false` targets, rather than guessing ids.
- Shared live-target and proof mechanics: [lane overview](../lanes/web.md).
