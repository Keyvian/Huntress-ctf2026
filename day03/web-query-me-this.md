# 🌐 Query Me This

| | |
|---|---|
| **Day** | 03 (released on GM day 19) |
| **Lane** | 🌐 Web Exploitation |
| **Challenge ID** | `web-exploitation-day-03-sqli` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/web/webrun.py`](../solvers/web/webrun.py) (`solve_sqli`), legacy [`solvers/web/webrun_sqli.py`](../solvers/web/webrun_sqli.py) |

## Prompt
> The search box trusts you a little too much. Ask the database one pointed question and read the row it was never supposed to show you.

## TL;DR
A **SQL injection** in a search box. The query wraps your input as `<col> LIKE '%q%'` over a table `articles`, and one row with `visibility='private'` is filtered out of the results and holds the proof. `UNION` and SQL comments are blocked, so the proof is extracted with a **blind boolean** injection, binary-searching the private row's text character by character.

## Artifact
No file; live target, proof `proof_<32 hex>`, answer id `proof-1` (mastery `proof-1..N`).

- Endpoint: `GET /lookup?q=<input>`.
- Backing table `articles(id, title, topic, summary, visibility)`, ~4 rows.
- The `visibility='private'` row is excluded from the rendered results; its `summary` is the proof.

Filtering observed: `UNION` and comment markers (`--`, `#`) are **stripped/blocked**; subqueries, `OR`, and functions (`length()`, `substr()`, `unicode()`) work.

## Solution
Because comments are blocked, the injection must close the `LIKE '%...%'` wrapper cleanly by ending inside a string literal. The working truth oracle for a boolean `B`:

```
q = zxq%' OR ((B) AND id=<anchor>) OR '1'='1
```

This returns the known anchor row **iff** `B` is true, so each probe is a visible/not-visible test. With that oracle:

1. Find the private row's id (the one not shown normally).
2. `length(summary)` via binary search on `B = (length((SELECT summary FROM articles WHERE visibility='private')) > N)`.
3. For each position `i`, binary-search `unicode(substr(summary,i,1))` to recover the character.
4. Reassemble `proof_…`.

Per-character probes are independent, so the search is threaded (`ThreadPoolExecutor`). Serial extraction is minutes; threaded it finishes in roughly 30–60 s — which matters a lot for the timed modes.

## Time Trial & Mastery
Played untimed via `run_for_time:false` (single omits it). Mastery bundles **2 sets**. The randomized part is the anchor/id values and the private row's content — all recovered live, so no reconfiguration is needed. SQLi is the slowest solver in the lane; threading keeps it comfortably inside even the untimed boot window.

## Lessons / gotchas
- With comments filtered, don't reach for `UNION`/`--`; the reliable primitive is boolean-blind with the payload ending inside a string so the trailing `'%'` closes naturally.
- Thread the per-character search — serial blind SQLi is painfully slow and was the only solver at real risk against a clock.
- Shared live-target and proof mechanics: [lane overview](../lanes/web.md).
