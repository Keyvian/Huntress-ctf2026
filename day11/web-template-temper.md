# 🌐 Template Temper

| | |
|---|---|
| **Day** | 11 (released on GM day 23) |
| **Lane** | 🌐 Web Exploitation |
| **Challenge ID** | `web-exploitation-day-11-template-temper` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/web/webrun.py`](../solvers/web/webrun.py) (`solve_ssti`) |

## Prompt
> The template engine is feeling expressive today — it evaluates everything it hears. Whisper the right incantation and make the server speak in expressions.

## TL;DR
A **server-side template injection (SpEL)**. A reflected parameter is evaluated as a Spring Expression Language template inside `{{ … }}`. The attempt proof is bound in the render context as the variable `{{objective}}`, so you just print it — no RCE needed.

## Artifact
No file; live target, proof `proof_<32 hex>`, answer id `proof-1` (mastery `proof-1..N`). Framework **Spring Boot** (skin "Message Mill"). `GET /api/clues`:

```json
{"feature_route": "/process-<hex>", "current_role": "...", "framework": "Spring Boot"}
```

Note: **no `secondary_route`** — the same clue shape as [Day 05 (admin)](../day05/web-administratively-speaking.md), so the two are told apart by live behavior.

## Solution
`GET <feature_route>?template=<x>` reflects `<x>` into a `<pre>` and evaluates `{{ … }}` as SpEL:

- `{{7*7}}` → `49`
- `{{''.getClass()}}` → `class java.lang.String`
- `{{T(java.lang.System)}}` → `class java.lang.System`

Only `{{…}}` fires; `${…}`, `#{…}`, Thymeleaf, and Jinja syntaxes do not. The proof is the context variable:

```
GET <feature_route>?template={{objective}}   →   proof_…
```

(`{{proof}}` / `{{flag}}` throw 500.) The solver finds the reflecting parameter by probing `{{7*7}}` across common names (`template` observed), then reads `{{objective}}`.

## Time Trial & Mastery
Played untimed via `run_for_time:false` (single omits it). Mastery bundles **3 sets**, types possibly mixed. Because the clue shape is `feature_route` with no `secondary_route` (identical to Day 05), `detect()` disambiguates by sending `?template={{7*7}}`: a reflected `49` (or framework "spring") ⇒ SSTI, otherwise ⇒ admin.

## Lessons / gotchas
- The context already contains the answer as `{{objective}}`; reaching for RCE gadgets is unnecessary and errors out.
- Days 11–13 all expose a generic `{feature_route[, secondary_route]}` clue shape with no unique marker, so `detect()` must probe the live routes to classify them — see [the lane overview](../lanes/web.md).
- Only the `{{…}}` delimiter is live; probe for the evaluating delimiter before assuming an engine.
