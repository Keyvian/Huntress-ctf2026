# 🌐 Fetch Quest

| | |
|---|---|
| **Day** | 15 (released on GM day 24) |
| **Lane** | 🌐 Web Exploitation |
| **Challenge ID** | `web-exploitation-day-15-fetch-quest` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/web/webrun.py`](../solvers/web/webrun.py) (`solve_ssrf`) |

## Prompt
> The server will fetch anything you point it at — including places you can't reach yourself. Send it on a quest to the internal service and collect what it brings back.

## TL;DR
A **server-side request forgery (SSRF)**. One route is a server-side fetcher that will request any absolute URL; another route is loopback-only (`internal_only`). Point the fetcher at the internal route over `127.0.0.1:8080` and it brings back the proof.

## Artifact
No file; live target, proof `proof_<32 hex>`, answer id `proof-1` (mastery `proof-1..N`). Framework **ASP.NET Core Minimal API** (skin "Fetch Quest"). `GET /api/clues`:

```json
{"framework": "...", "feature_route": "/action-<hex>", "secondary_route": "/account-<hex>", "current_role": "..."}
```

This is the same generic `{feature_route, secondary_route}` shape as Days 12/13. The discriminator: `GET secondary_route` → **403 `internal_only`**.

## Solution
`feature_route` is a fetcher: `GET ?url=<absolute>` (parameter `url`; wrong names → `400 absolute_url_required`; unreachable host → `502 fetch_failed`). The secondary route trusts only loopback callers. SSRF the fetcher at the internal service:

```
GET <feature_route>?url=http://127.0.0.1:8080<secondary_route>
→ {"ok":true,"effect":"internal_service_reached","evidence":"proof_…"}
```

The internal port was **8080** (not 80/5000). The solver first finds the recognized `url` parameter name, then sweeps host × port with 8080 first (`_SSRF_BASES`).

## Time Trial & Mastery
Played untimed via `run_for_time:false` (single omits it). Mastery bundles **4 sets** (the mastery set count steps up to 4 here), types possibly mixed. `detect()` probes `GET secondary_route` and keys on `internal_only` in the body **before** the mass-assignment 403 check (Day 15's secondary is also a 403, so ordering matters).

## Lessons / gotchas
- The internal service listens on `127.0.0.1:8080`; sweep the port — the obvious 80/5000 fail.
- Day 15 shares the feat+sec clue shape with Days 12/13/21/25, all disambiguated by the secondary route's body — see [lane overview](../lanes/web.md).
- This fetcher-plus-internal-service pattern returns, richer, in [Day 27 (SSRF + object authz)](../day27/web-internal-affairs.md).
