# 🌐 The API Has Opinions

| | |
|---|---|
| **Day** | 14 (released on GM day 24) |
| **Lane** | 🌐 Web Exploitation |
| **Challenge ID** | `web-exploitation-day-14-the-api-has-opinions` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/web/webrun.py`](../solvers/web/webrun.py) (`solve_apiauthz`) |

## Prompt
> Take inventory of the API's little kingdom — every endpoint, every field, every function. Somewhere in there, authorization is merely a suggestion.

## TL;DR
A **combinatorial API authorization gap**. The feature route needs an `id`, a `fields`, and an `action`. The server blesses only the public sample tuple and forbids *any single* raised axis — but the **combination** of the protected id + privileged field (`note`) + privileged action (`export`) slips through together.

## Artifact
No file; live target, proof `proof_<32 hex>`, answer id `proof-1` (mastery `proof-1..N`). Framework **Jakarta Servlet on Tomcat** (skin "WAR Room"). `GET /api/clues`:

```json
{"feature_route": "/execute-<hex>", "inventory_route": "/api/inventory",
 "current_role": "analyst", "protected_reference": <int>}
```

`GET /api/inventory`:

```json
{"query_parameters": ["id","fields","action"], "fields": ["title","note"],
 "actions": ["view","export"], "public_reference": <int>,
 "sample": {"id": <public>, "fields": "title", "action": "view"}}
```

## Solution
The feature route requires all three parameters (else `400 id_fields_action_required`). The access decision returns `403 field_action_forbidden` whenever exactly one axis is raised above the public sample:

- protected `id` + `fields=title` + `action=view` → 403
- public `id` + `fields=note` + `action=view` → 403
- public `id` + `fields=title` + `action=export` → 403

But raising **all three at once** passes:

```
GET <feature_route>?id=<protected_reference>&fields=note&action=export
→ {"ok":true,"effect":"api_field_action_authorization_bypassed","evidence":"proof_…"}
```

The solver brute-forces the id × field × action cross-product (≤ 8 GETs), trying the non-sample value of each axis first. HTTP parameter pollution and method tampering were red herrings — it is purely a combinatorial-authz hole.

## Time Trial & Mastery
Played untimed via `run_for_time:false` (single omits it). Mastery bundles **3 sets**, types possibly mixed. `detect()` keys on the unique markers `inventory_route` + `protected_reference`. The inventory route is read live, so the exact field/action vocabulary is never hard-coded.

## Lessons / gotchas
- The gap is in the *combination*: testing each axis alone makes it look fully locked. Raise all three together.
- `protected_reference` is shared with [Day 18 (GraphQL)](../day18/web-resolver-revolt.md); `detect()` routes to GraphQL first when there is no `inventory_route` and GraphQL framework/note markers are present, else apiauthz — see [lane overview](../lanes/web.md).
