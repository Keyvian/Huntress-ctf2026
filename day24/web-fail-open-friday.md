# 🌐 Fail Open Friday

| | |
|---|---|
| **Day** | 24 (released on GM day 28) |
| **Lane** | 🌐 Web Exploitation |
| **Challenge ID** | `web-exploitation-day-24-fail-open-friday` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/web/webrun.py`](../solvers/web/webrun.py) (`solve_failopen`) |

## Prompt
> The remote policy decoder is part of an access decision. A valid public decision is documented in the application; investigate what happens when that decision cannot be decoded.

## TL;DR
A **fail-open authorization** bug. The route makes an access decision from a "remote policy" blob (prefix + base64url JSON). The secure behavior is to DENY when the decision can't be decoded, but a decode exception is caught and the code ALLOWS. Send the right prefix with an undecodable payload to trigger the caught-exception path.

## Artifact
No file; live target, proof `proof_<32 hex>`, answer id `proof-1` (mastery `proof-1..N`). Framework **ASP.NET Core Razor Pages**. `GET /api/clues`:

```json
{"framework": "ASP.NET Core Razor Pages", "feature_route": "/inspect-<hex>",
 "policy_format_route": "/api/policy-format", "current_role": "analyst",
 "expected_behavior": "deny access when the policy service is unavailable"}
```

`GET /api/policy-format`:

```json
{"query_parameter": "policy", "prefix": "remote:<12 hex>:",
 "encoding": "base64url UTF-8 JSON", "sample_decision": {"scope":"public","allow":true},
 "sample_encoded": "<b64url>"}
```

(the sample decodes to PascalCase `{"Scope":"public","Allow":true}`).

## Solution
The decision matrix shows this is **not** a forgery bug:

| `policy` value | result |
|---|---|
| `prefix` + sample | 200, `policy:"standard"` (public, no proof) |
| `prefix` + `{"Scope":"protected"/"admin","Allow":true}` | **403 `policy_denied`** (a forged allow is still evaluated and denied) |
| wrong/empty prefix, or no prefix | 400 `remote_policy_required` (prefix validated up front) |
| **correct prefix + undecodable payload**, or **prefix alone** | **200 `exceptional_condition_fail_open`**, `evidence:"proof_…"` |

So the exploit is the caught-exception path, not a forged decision:

```
GET <feature_route>?policy=<prefix>!!!not-base64!!!
→ {"ok":true,"effect":"exceptional_condition_fail_open","evidence":"proof_…"}
```

`solve_failopen` reads `query_parameter` + `prefix` from the format route and sends `prefix` + garbage (and prefix-only, prefix + base64url-of-non-JSON) to drive the decode exception.

## Time Trial & Mastery
Played untimed via `run_for_time:false` (single omits it). Mastery bundles **5 sets**, types possibly mixed. `detect()` keys on the unique `policy_format_route` and runs it **before** the feature-route block (Day 24 has a `feature_route` but no `secondary_route`).

## Lessons / gotchas
- A forged "allow" decision is *still denied* — the prefix is validated and the decision honestly evaluated. The win is making decode *throw*, so the catch-all allows.
- Keep the valid prefix (it's checked first) but hand it bytes that can't decode.
- Shared live-target and proof mechanics: [lane overview](../lanes/web.md).
