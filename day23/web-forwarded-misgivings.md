# 🌐 Forwarded Misgivings

| | |
|---|---|
| **Day** | 23 (released on GM day 27) |
| **Lane** | 🌐 Web Exploitation |
| **Challenge ID** | `web-exploitation-day-23-forwarded-misgivings` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/web/webrun.py`](../solvers/web/webrun.py) (`solve_forwarded`) |

## Prompt
> The app believes whatever the proxy whispers in its ear. Whisper the right header and stroll down the protected path as an insider.

## TL;DR
A **trusted reverse-proxy header spoof**. The app derives the client IP from a blindly-trusted forwarded header. Set `X-Forwarded-For: 127.0.0.1` and the loopback-only feature route opens.

## Artifact
No file; live target, proof `proof_<32 hex>`, answer id `proof-1` (mastery `proof-1..N`). Framework **Micronaut** (skin "Header House"). `GET /api/clues`:

```json
{"framework": "Micronaut", "feature_route": "/action-<hex>", "current_role": "analyst", "deployment": "trusted_reverse_proxy"}
```

The unique clue key `deployment` identifies this type.

## Solution
A plain `GET feature_route` → `403 {"error":"loopback_only","evaluated_client":"10.1.0.0"}` (our real edge IP). The app trusts a forwarded header for the client IP:

```
GET <feature_route>
X-Forwarded-For: 127.0.0.1
→ 200 {"ok":true,"effect":"proxy_trust_admin_bypass","evaluated_client":"127.0.0.1","evidence":"proof_…"}
```

Only `X-Forwarded-For` worked here (`X-Real-IP`, `X-Client-IP`, `True-Client-IP`, `X-Forwarded-Host`, and `Forwarded:` all stayed 403); Micronaut honors the **leftmost** XFF entry. `solve_forwarded` sweeps forwarded-header names × loopback values, trying `127.0.0.1` first.

## Time Trial & Mastery
Played untimed via `run_for_time:false` (single omits it). Mastery bundles **5 sets**, types possibly mixed. `detect()` keys on the unique `deployment` clue and runs it **before** the feature-route block (Day 23 has a `feature_route` but no `secondary_route`).

## Lessons / gotchas
- Only `X-Forwarded-For` was honored; don't assume the whole forwarded-header family is trusted.
- The response echoes `evaluated_client`, which is a handy oracle for which header/value the app actually believed.
- This solver is reused by [Day 30 (Framework Roulette)](../day30/web-framework-roulette.md), whose two-layer variant adds a forwarded *role* claim on top of the forwarded IP — see [lane overview](../lanes/web.md).
