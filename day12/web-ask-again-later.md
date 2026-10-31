# 🌐 Ask Again Later

| | |
|---|---|
| **Day** | 12 (released on GM day 23) |
| **Lane** | 🌐 Web Exploitation |
| **Challenge ID** | `web-exploitation-day-12-ask-again-later` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/web/webrun.py`](../solvers/web/webrun.py) (`solve_delayed_sqli`) |

## Prompt
> No answer right now? Fine. Plant your question inside the data and come back later — the delayed echo tells all.

## TL;DR
A **deferred (second-order) SQL injection**. You POST a stored "filter" that is later concatenated into a `WHERE visibility='<filter>'` query when a separate result route runs. A boolean-OR-with-comment payload in the stored filter reveals the private row.

## Artifact
No file; live target, proof `proof_<32 hex>`, answer id `proof-1` (mastery `proof-1..N`). Framework **Sinatra** (skin "Report Replay"). `GET /api/clues`:

```json
{"framework": "Sinatra", "feature_route": "/submit-<hex>", "secondary_route": "/result-<hex>", "current_role": "..."}
```

`feature_route` GET = `405 post_required`; `POST {"filter": <v>}` stores the query (`{"ok":true,"saved":true}`). `secondary_route` GET runs it later and returns `{"rows":[…]}`.

## Solution
The stored filter lands inside `WHERE visibility='<filter>'`. A benign `filter:"public"` returns only the public row; inject to also return the private one:

1. `POST <feature_route>` with `{"filter": "public' OR '1'='1' -- "}` — note the **trailing space** after `--`.
2. `GET <secondary_route>` → `{"rows":["Ordinary workspace note","proof_…"], "effect":"delayed_query_revealed_private_row"}`.

`UNION` / `ORDER BY` error (500); the boolean-OR-with-comment form works. The injection is "deferred" because it only executes when the second route reads the stored filter.

## Time Trial & Mastery
Played untimed via `run_for_time:false` (single omits it). Mastery bundles **3 sets**, types possibly mixed. Day 12 and [Day 13 (mass-assignment)](../day13/web-posted-too-much.md) share the exact `{feature_route, secondary_route}` clue shape, so `detect()` probes `GET secondary_route`: 200 rows / `delayed_query` / `private_row` ⇒ delayed-SQLi; a 403 / `administrator_required` ⇒ mass-assignment. (Framework Sinatra vs NestJS is the tiebreak.)

## Lessons / gotchas
- The injection point is *stored*, not reflected — POST then GET a different route; a single request shows nothing.
- Mind the trailing space after `--`, or the comment doesn't terminate the quote correctly.
- Shared live-target and proof mechanics, plus the days 11–13 disambiguation logic: [lane overview](../lanes/web.md).
