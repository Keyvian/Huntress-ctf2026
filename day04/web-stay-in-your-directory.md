# 🌐 Stay in Your Directory

| | |
|---|---|
| **Day** | 04 (released on GM day 20) |
| **Lane** | 🌐 Web Exploitation |
| **Challenge ID** | `web-exploitation-day-04-lfi` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/web/webrun.py`](../solvers/web/webrun.py) (`solve_lfi`) |

## Prompt
> The viewer should stay inside its pages directory. An operations note says the attempt proof is mounted at /run/huntress/objective.txt. Can you make the viewer cross that boundary?

## TL;DR
A **local file inclusion / path traversal**. A document viewer includes `pages/<doc>` with no sanitization, and the prompt tells you the proof lives at the absolute path `/run/huntress/objective.txt`. A plain `../`-traversal out of `pages/` reads it.

## Artifact
No file; live target, proof `proof_<32 hex>`, answer id `proof-1` (mastery `proof-1..N`). Usually **PHP + Apache** (skins "Runbook Nook", "Page Turner"; sometimes Node). The viewer is `GET /<name>.php?doc=<file>` where the script name and parameter name are randomized (e.g. `reader.php?doc=`, `notes.php?doc=`). The proof path is given in the prompt: **`/run/huntress/objective.txt`**.

## Solution
Traverse out of the `pages/` directory to the absolute objective path:

```
GET /reader.php?doc=../../../../../../../../run/huntress/objective.txt
```

Eight or more `../` is plenty; extra depth is harmless because traversal stops at filesystem root. No encoding or wrapper tricks were needed — `php://filter`, leading `/abs`, and `%00` were tried and were **not** required (and mostly failed). The include simply concatenates the user path onto `pages/` with no normalization.

The solver detects the type from a `*.php?<param>=` viewer link plus the "stay in the approved folder" wording, discovers the script/param names from the homepage, and requests the objective path through the viewer.

## Time Trial & Mastery
Played untimed via `run_for_time:false` (single omits it). Mastery bundles **2 sets**, types possibly mixed. The only randomized pieces are the script and parameter names, both read from the live homepage, so the exploit URL is built per attempt.

## Lessons / gotchas
- The proof path `/run/huntress/objective.txt` is reused by the OS-command-injection challenge ([Day 16](../day16/web-shell-company.md)) — same objective mount, different primitive.
- Don't over-engineer: no filter bypass, null byte, or `php://` wrapper was necessary; straight traversal to the absolute path worked.
- Shared live-target and proof mechanics: [lane overview](../lanes/web.md).
