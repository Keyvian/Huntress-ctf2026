# 🌐 Double Spent

| | |
|---|---|
| **Day** | 21 (released on GM day 27) |
| **Lane** | 🌐 Web Exploitation |
| **Challenge ID** | `web-exploitation-day-21-double-spent` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/web/webrun.py`](../solvers/web/webrun.py) (`solve_doublespend`) |

## Prompt
> One credit, two purchases. The ledger can't count what it can't see coming — race it and spend the same credit twice.

## TL;DR
A **double-spend / TOCTOU race**. A one-shot credit is spent with a non-atomic check-then-decrement. Fire a barrier-synchronized burst of concurrent POSTs so two both pass the `credits>0` check and both decrement, driving the balance negative; the audit route then reveals the proof.

## Artifact
No file; live target, proof `proof_<32 hex>`, answer id `proof-1` (mastery `proof-1..N`). Framework **Rails**. `GET /api/clues`:

```json
{"framework": "Rails", "feature_route": "/execute-<hex>", "secondary_route": "/audit-<hex>", "current_role": "..."}
```

Generic feat+sec shape (same as Days 12/13/15). A fresh target holds exactly **1 credit**.

## Solution
`feature_route` GET = `405 post_required`. A POST spends a credit with a non-atomic guard. Behavior observed:

- A single legitimate POST: `credits 1→0`, ok. Every POST after: `409 {"ok":false,"credits":0,"effect":"credit_unavailable"}`.
- `GET secondary_route` (audit): `403 {"error":"credit_not_overspent","credits":0}` until credits go **negative**.

The exploit is a race from a **fresh** instance:

```
fire M concurrent POSTs behind a thread barrier  →  ≥2 pass credits>0 and both decrement  →  credits:-1
GET secondary_route  →  {"effect":"credit_overspent","evidence":"proof_…"}
```

Racing from `credits:0` does nothing (the guard refuses at ≤0 without decrementing — confirmed with 100-way bursts × 6 rounds), so the burst **must be the first writes** on a fresh instance. `solve_doublespend` uses 25 threads behind a barrier, 5 rounds, and checks the audit for an already-won proof first.

## Time Trial & Mastery
Played untimed via `run_for_time:false` (single omits it). Mastery bundles **4 sets**, types possibly mixed. Day 21 shares the feat+sec shape, so `detect()` probes `GET secondary_route` and keys on `credit` / `overspent` in the body **first** (no other feat+sec type mentions credits). With `detect()` routing Day 21 to doublespend, webrun's *first* contact is the burst, so fresh variants solve on first touch.

## Lessons / gotchas
- **The burst must be the first writes.** A pre-fix backlog once misdetected this as mass-assignment and POSTed to `/execute`, spending the single credit and wedging the instance at 0 — a consumed single-solve instance only reprovisions after the ~30-min idle reset (`retry` is `operation_not_allowed` for single). The automation had to be paused and the slot left to idle before a clean fresh burst.
- Racing an already-zeroed balance is useless; the guard just refuses without decrementing.
- Shared live-target mechanics and the feat+sec disambiguation order: [lane overview](../lanes/web.md).
