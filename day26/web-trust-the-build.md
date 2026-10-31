# 🌐 Trust the Build

| | |
|---|---|
| **Day** | 26 (released on GM day 29) |
| **Lane** | 🌐 Web Exploitation |
| **Challenge ID** | `web-exploitation-day-26-trust-the-build` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/web/webrun.py`](../solvers/web/webrun.py) (`solve_trustbuild`) |

## Prompt
> The updater trusts its packages like old friends. Slip a tampered dependency into the build and watch it install your version of the truth.

## TL;DR
A **signed-manifest integrity bypass** (supply chain). Activation never re-verifies the artifact bytes against the signed `artifact_sha256`, so you can flip the manifest's `hook` to a restricted one while keeping the original (now stale) signature — and it activates.

## Artifact
No file; live target, proof `proof_<32 hex>`, answer id `proof-1` (mastery `proof-1..N`). Framework **Fiber/Go**. `GET /api/clues`:

```json
{"current_role": "analyst", "feature_route": "/inspect-<hex>", "framework": "Fiber",
 "update_feed": "/api/updates", "update_policy": "/api/update-policy"}
```

- `GET /api/updates` → `{updates:[{package, version, artifact:{build, hook:"passive_health"}, artifact_sha256:<sha256 of compact json of artifact>, signature:<64 hex>}]}`.
- `GET /api/update-policy` → `{hooks:[{access:"routine", name:"passive_health"}, {access:"restricted", name:"privileged_export"}], integrity_contract:"…activation must verify the artifact bytes against it."}`.

## Solution
`feature_route` GET → `405 post_required`; **POST the manifest JSON** to activate. Posting the manifest as-is → `{"effect":"routine_update_activated"}` (no proof; `passive_health` is routine).

The flaw: activation does **not** re-verify the artifact bytes against the signed `artifact_sha256` (the integrity contract is a lie). So POST the manifest with `artifact.hook` flipped to the **restricted** hook while keeping the original `artifact_sha256` + `signature` unchanged:

```
POST <feature_route>  {…, "artifact": {"build": …, "hook": "privileged_export"},
                       "artifact_sha256": <original>, "signature": <original>}
→ {"ok":true,"effect":"unverified_update_activated","evidence":"proof_…"}
```

Changing the hook changes the real artifact hash, but the stale signed sha/signature are never checked against the bytes. (Wrapping the manifest in `{manifest:…}` / `{update:…}` → `422 update_not_found`; the body **is** the bare manifest.) `solve_trustbuild` reads `updates[0]` + the restricted hook name (access ≠ routine) from the policy and POSTs each update with `artifact.hook` = restricted, preserving sha256 + signature.

## Time Trial & Mastery
Played untimed via `run_for_time:false` (single omits it). Mastery bundles **5 sets**, types possibly mixed. `detect()` keys on the unique `update_feed` + `update_policy` and runs it **before** the feature-route block (Day 26 has a `feature_route` but no `secondary_route`).

## Lessons / gotchas
- **Keep the original signature.** The point is that it's never checked; re-signing is both impossible and unnecessary.
- The restricted hook name comes from the policy's `access` field, not a guess.
- Shared live-target and proof mechanics: [lane overview](../lanes/web.md).
