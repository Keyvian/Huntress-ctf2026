# 🌐 Framework Roulette

| | |
|---|---|
| **Day** | 30 (released on GM day 31) |
| **Lane** | 🌐 Web Exploitation |
| **Challenge ID** | `web-exploitation-day-30-framework-roulette` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/web/webrun.py`](../solvers/web/webrun.py) (`solve_forwarded`, per-target `detect()` + dispatch) |

## Prompt
> New stack, no map, no familiar names. Everything you've learned, none of your crutches — prove the skills travel.

## TL;DR
The first **final-gauntlet** challenge: a known vulnerability class reskinned in an unfamiliar framework with randomized route and error names, so pattern-matching on skins no longer works and you must classify by behavior. Mastery **mixes the whole catalog**. The one genuinely new shape is a **two-layer forwarded-trust**: forge the client IP (`X-Forwarded-For: 127.0.0.1`) *and* a forwarded role claim whose header **name is leaked in the response `Vary` header** and whose value is `administrator`.

## Artifact
No file; live target, proof `proof_<32 hex>`, answer id `proof-1` (mastery `proof-1..N`). Single/Time Trial = one target; **Mastery bundles 6 sets** that mix types — e.g. a bundle with backup ("Status Sprout") + idor ("Pocket SOC") + sqli/reflect ("Search Party") + lfi ("Page Turner") + a pure Day-23 forwarded-IP + the two-layer forwarded-role below. The early-catalog skins have no `/api/clues` (the HTML heuristics already classify them).

The new shape (an ASP.NET Core Blazor Server skin) has `GET /api/clues`:

```json
{"framework": "...", "feature_route": "/inspect-<hex>", "component_route": "/blazor", "current_role": "analyst"}
```

— the generic feature-route-no-secondary shape, with no unique clue key.

## Solution
A bare `GET feature_route` → `403 {"error":"gateway_context_rejected","evaluated_client":"10.1.0.0"}` (our real edge IP). There are two layers:

**Layer 1 — forwarded IP trust** (same as [Day 23](../day23/web-forwarded-misgivings.md)):

```
GET <feature_route>
X-Forwarded-For: 127.0.0.1
→ 403 {"error":"topology_proof_rejected","policy":"staff_only"}
```

Only `127.0.0.1` passes, leftmost honored. That clears the IP gate but hits a second gate.

**Layer 2 — forwarded role claim**: the second gate wants a role header, but its **name is randomized per instance** and **disclosed in the response `Vary` header** (`Vary: x-arena-<hex>` — literally "no familiar names"). The value is `administrator` (not "staff", despite `policy:staff_only`; the homepage hints "administrative actions should remain outside this role"):

```
GET <feature_route>
X-Forwarded-For: 127.0.0.1
x-arena-<hex>: administrator
→ 200 {"ok":true,"effect":"unseen_trust_boundary_generalized","evidence":"proof_…"}
```

587 common role-header names × values were all flat-rejected — the only way in is reading the `Vary`-disclosed header name. This is folded into `solve_forwarded`: after the IP sweep, it GETs the feature route with XFF=127.0.0.1, reads the non-standard `Vary` tokens (plus generic fallbacks), and sweeps `_FWD_ROLES` with `administrator` first. `detect()` routes a feature-route-no-secondary target to `forwarded` when a bare GET body shows `evaluated_client` / `gateway_context` / `loopback` / `forwarded`; the mastery bundle's other targets go through normal per-target `detect()` + fallback.

## Time Trial & Mastery
Played untimed via `run_for_time:false` (single omits it). Mastery bundles **6 sets** and MIXES the whole catalog, so the per-target `detect()` + dispatch is essential — each target is classified and solved independently, one proof per target (`proof-1..6`). Confirmed single/Time Trial CORRECT and Mastery 6/6 CORRECT.

## Lessons / gotchas
- "None of your crutches" is the literal theme: route/error names are randomized, so classify by *response behavior*, not by skin strings.
- The randomized role-header name is the trick — read it from the `Vary` header rather than brute-forcing names (587 guesses failed).
- The role value is `administrator`, even though the gate's policy says `staff_only`.
- Shared live-target mechanics and the full type catalog: [lane overview](../lanes/web.md).
