# 🌐 Shell Company

| | |
|---|---|
| **Day** | 16 (released on GM day 25) |
| **Lane** | 🌐 Web Exploitation |
| **Challenge ID** | `web-exploitation-day-16-shell-company` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/web/webrun.py`](../solvers/web/webrun.py) (`solve_cmdinject`) |

## Prompt
> It's a shell company: all front, no substance — until your input gets a little too close to a real shell. Give it something to do and leave your mark.

## TL;DR
An **OS command injection**. A diagnostic endpoint runs `ls -ld <path>` with the `path` parameter concatenated into the shell unsanitized. Append `; cat /run/huntress/objective.txt` and the proof appears in the command's stdout.

## Artifact
No file; live target, proof `proof_<32 hex>`, answer id `proof-1` (mastery `proof-1..N`). Framework **Gin/Go** (skin "Worker Window"). `GET /api/clues`:

```json
{"current_role": "...", "feature_route": "/process-<hex>", "framework": "Gin",
 "input_parameter": "path", "example_path": "/app/static"}
```

The unique clue keys `input_parameter` + `example_path` identify this type.

## Solution
`GET <feature_route>?path=<v>` runs a shell command (`ls -ld <path>`) with the parameter concatenated in. Shell metacharacters inject:

```
GET <feature_route>?path=/app/static; cat /run/huntress/objective.txt
→ {"ok":true,"effect":"worker_command_completed","stdout":"…proof_…"}
```

Both `;` and `|` work as separators (even a bare `; cat …`). Command substitution without a `$` (`` `…` ``) returns `400 diagnostic_failed`, so `;`/`|` are the reliable primitives. The proof file is `/run/huntress/objective.txt` — the same objective mount used by the [Day 04 LFI](../day04/web-stay-in-your-directory.md).

The solver reads `input_parameter` and `example_path` from the clues and appends `; cat <objective>` (plus `|`, bare, glob, and `find`/`grep` fallbacks).

## Time Trial & Mastery
Played untimed via `run_for_time:false` (single omits it). Mastery bundles **4 sets**, types possibly mixed. `detect()` keys on `input_parameter` + `example_path`. The parameter name and example path are read live.

## Lessons / gotchas
- Start from the legitimate `example_path` so the base command succeeds, then chain your own command after `;` or `|`.
- `$(...)`-style substitution failed here; prefer plain separators.
- Shared objective mount with the LFI challenge; shared live-target mechanics: [lane overview](../lanes/web.md).
