# 🌐 Reflect Upon This

| | |
|---|---|
| **Day** | 06 (released on GM day 21) |
| **Lane** | 🌐 Web Exploitation |
| **Challenge ID** | `web-exploitation-day-06-reflect-upon-this` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/web/webrun.py`](../solvers/web/webrun.py) (`solve_reflect`) |

## Prompt
> This page repeats everything you tell it. Make it repeat something that talks back — land the isolated callback and watch it reflect.

## TL;DR
A **reflected XSS** sink whose proof is gated behind a server-side "isolated browser callback." The reflection is real, but you don't need a browser: the callback route hands over the proof when given the right `nonce` *and* a `Referer` pointing at the reflecting page — the server's stand-in for "the injected script fired."

## Artifact
No file; live target, proof `proof_<32 hex>`, answer id `proof-1` (mastery `proof-1..N`). Framework **Fastify** (skin "Search Mirror"). `GET /api/clues`:

```json
{"feature_route": "/execute-<hex>", "secondary_route": "/callback-<hex>", "callback_nonce": "<12 hex>"}
```

`feature_route?q=<x>` reflects `<x>` raw into a `#preview` element — a genuine reflected-XSS sink. The proof is not in the reflection; it is behind the callback route.

## Solution
No real DOM is required. The callback route returns the proof only when the request looks like it came from the reflecting page:

```
GET <secondary_route>?nonce=<callback_nonce>
Referer: <feature_route page URL>
```

→ `{"effect": "isolated_browser_callback", "evidence": "proof_…"}`.

- The `nonce` (parameter literally named `nonce`) comes straight from `/api/clues`.
- The `Referer` must point at the `feature_route` page.
- Either alone returns `403 browser_callback_required`.

The solver reads the clue fields, builds the callback request with both the nonce param and the Referer header, and extracts `proof_`.

## Time Trial & Mastery
Played untimed via `run_for_time:false` (single omits it). Mastery bundles **2 sets**, types possibly mixed. `detect()` recognizes this type immediately by the `callback_nonce` clue key. Route names and nonce are randomized per attempt and read live.

## Lessons / gotchas
- The challenge *looks* like it wants a headless browser to execute the XSS; it actually only models the callback with a `nonce` + `Referer` check, so plain HTTP wins.
- `callback_nonce` is a unique clue key — a clean discriminator for `detect()`.
- Shared live-target and proof mechanics: [lane overview](../lanes/web.md).
