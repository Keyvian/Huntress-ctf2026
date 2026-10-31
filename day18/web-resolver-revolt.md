# 🌐 Resolver Revolt

| | |
|---|---|
| **Day** | 18 (released on GM day 25) |
| **Lane** | 🌐 Web Exploitation |
| **Challenge ID** | `web-exploitation-day-18-resolver-revolt` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/web/webrun.py`](../solvers/web/webrun.py) (`solve_graphql`) |

## Prompt
> Discover the schema and reach a resolver whose field-level control is incomplete. Vary the protocol surface without changing the underlying authorization discipline.

## TL;DR
A **GraphQL field-level authorization bypass**. The case *index* only lists references, but the single-record resolver `case(id)` returns the full object — including a private `note` — with no field-level check. Query the protected reference directly and read its note.

## Artifact
No file; live target, proof `proof_<32 hex>`, answer id `proof-1` (mastery `proof-1..N`). Framework **GraphQL.js** (skin "Graph Garden"). `GET /api/clues`:

```json
{"current_user": "analyst", "feature_route": "/inspect-<hex>", "protected_reference": "<int>",
 "note": "The case index lists references; field access is checked by each resolver."}
```

`feature_route` is the GraphQL endpoint (POST `{query}`; GET → `404 not_found`). Introspection is open.

## Solution
Schema (via open introspection):

- `Query.caseIndex` → `[CaseReference{id,title,visibility}]` (the privileged one shows `visibility:"reference only"`)
- `Query.case(id)` → `Case{id,title,note}`

The index only lists references, but the record resolver returns the full `Case` including the private `note` with no per-field check:

```graphql
{ case(id: <protected_reference>) { id title note } }
```

→ `note` holds `proof_…`. The solver tries the direct `case(id){id title note}` (int and string id), then falls back to introspection: find the record field taking an `id` argument, select its scalar fields, and query `protected_reference` plus any index ids.

## Time Trial & Mastery
Played untimed via `run_for_time:false` (single omits it). Mastery bundles **4 sets**, types possibly mixed. `protected_reference` is shared with [Day 14 (API authz)](../day14/web-the-api-has-opinions.md), so `detect()` routes to GraphQL first when there is **no** `inventory_route` and GraphQL is flagged by framework, a "resolver" note, or the `current_user` key — otherwise apiauthz.

## Lessons / gotchas
- "Vary the protocol surface" is the hint to switch from the index query to the record resolver; the authorization discipline (field checks) is what's incomplete, not the transport.
- Introspection is open — use it to find the record field and its scalar fields when the direct guess doesn't fit the variant.
- Shared live-target mechanics and the Day 14/18 disambiguation: [lane overview](../lanes/web.md).
