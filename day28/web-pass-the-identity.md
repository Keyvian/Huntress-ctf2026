# 🌐 Pass the Identity

| | |
|---|---|
| **Day** | 28 (released on GM day 30) |
| **Lane** | 🌐 Web Exploitation |
| **Challenge ID** | `web-exploitation-day-28-pass-the-identity` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/web/webrun.py`](../solvers/web/webrun.py) (`solve_delegidentity`) |

## Prompt
> Your identity is a hall pass — and this building accepts photocopies. Carry it across a delegated service boundary and cash it in where it doesn't belong.

## TL;DR
A **delegated-identity passthrough trust**. The feature route is a service boundary that blindly trusts a forwarded identity header. Present the privileged identity (`records_owner`) in that header and the server acts as it.

## Artifact
No file; live target, proof `proof_<32 hex>`, answer id `proof-1` (mastery `proof-1..N`). Framework **Axum/Rust** (skin "Caller Courier"). `GET /api/clues`:

```json
{"current_role": "analyst", "feature_route": "/execute-<hex>", "framework": "Axum",
 "identity_directory_route": "/api/identities", "secondary_route": "/result-<hex>"}
```

`GET /api/identities` → `{"caller":"analyst","records_owner":"executive"}` (caller = us; `records_owner` = the privileged identity to impersonate). A bare `GET feature_route` (and secondary) → `403 delegated_identity_rejected`.

## Solution
The feature route is a "delegated service boundary" that trusts a forwarded identity header (a photocopy, no verification). Present the privileged identity:

```
GET <feature_route>
X-Delegated-User: executive
→ 200 {"ok":true,"effect":"delegated_identity_trusted","evidence":"proof_…"}
```

The header **name** is randomized per variant, so `solve_delegidentity` sweeps delegated-identity header names (`X-Delegated-User`/`-Identity`/`-Caller`, `X-On-Behalf-Of`, `X-Identity`, `X-Forwarded-User`, `X-Remote-User`, `X-User`, `X-Caller`, `X-Actor`, `X-Impersonate`, `X-Run-As`, …) × the `records_owner` value × the feature and secondary routes (GET).

## Time Trial & Mastery
Played untimed via `run_for_time:false` (single omits it). Mastery bundles **5 sets**, types possibly mixed. `detect()` keys on the unique `identity_directory_route`. Day 28 has **both** `feature_route` and `secondary_route` (both 403 `delegated_identity_rejected` on a bare request), so this check runs **before** the feat+sec block, or the 403 secondary would misdetect as mass-assignment.

## Lessons / gotchas
- Read the identity directory for `records_owner` — don't guess the privileged name; it's disclosed.
- The header name is randomized, so sweep a superset of delegated-identity header names rather than assuming `X-Forwarded-User`.
- Shared live-target mechanics and the detection ordering: [lane overview](../lanes/web.md).
