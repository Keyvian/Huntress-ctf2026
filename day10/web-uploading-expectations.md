# 🌐 Uploading Expectations

| | |
|---|---|
| **Day** | 10 (released on GM day 22) |
| **Lane** | 🌐 Web Exploitation |
| **Challenge ID** | `web-exploitation-day-10-uploading-expectations` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/web/webrun.py`](../solvers/web/webrun.py) (`solve_upload`) |

## Prompt
> The upload form has standards. Low ones. Slip your file past the bouncer and get it served from somewhere it was never meant to live.

## TL;DR
An **upload filter bypass leading to SSTI**. The nominal policy claims to accept only `.txt` / `text/plain`, but the server decides how to render a file purely by a lowercase `.html` filename suffix, ignoring `content_type`. Upload a `.html` file whose body is `{{objective}}`; the staff preview evaluates double-brace fields and renders the proof.

## Artifact
No file; live target, proof `proof_<32 hex>`, answer id `proof-1` (mastery `proof-1..N`). Framework **Go net/http** (skin "File Counter"). `GET /api/clues`:

```json
{"feature_route": "/inspect-<hex>", "render_route": "/result-<hex>",
 "preview_guide": "/preview-guide",
 "upload_policy": "Only .txt … text/plain",
 "upload_shape": "POST JSON: filename, content, content_type"}
```

`preview_guide` reveals that staff HTML previews evaluate double-brace fields and that the objective field is `{{objective}}`.

## Solution
The filter is nominal — a filename ending in lowercase `.html` is served as a rendered template **regardless of `content_type`**, while `.HTML`, `.html.`, `.html.txt`, and `.txt` are all served as raw `text/plain` (no evaluation).

1. `POST <feature_route>` with `{"filename": "exploit.html", "content": "{{objective}}", "content_type": "text/plain"}`.
2. Response: `{"path": "/result-<hex>?file=exploit.html"}`.
3. `GET` that path; the preview renderer evaluates `{{objective}}` → `proof_…`.

The solver reads the objective field name from `preview_guide` (default `objective`) and the upload shape from the clues.

## Time Trial & Mastery
Played untimed via `run_for_time:false` (single omits it). Mastery bundles **3 sets**, types possibly mixed. `detect()` keys on `upload_shape` / `upload_policy` / `render_route`. The content-type is cosmetic; only the lowercase `.html` suffix matters.

## Lessons / gotchas
- The bypass hinges on how the server *routes rendering*, not on MIME at all — a `.html` name alone flips raw text into a rendered template.
- The template context exposes the proof as `{{objective}}`; no RCE is needed. This is the first of the double-brace-template family — see [Day 11 (SSTI/SpEL)](../day11/web-template-temper.md).
- Shared live-target and proof mechanics: [lane overview](../lanes/web.md).
