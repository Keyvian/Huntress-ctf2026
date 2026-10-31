# 🌐 Back Up a Minute

| | |
|---|---|
| **Day** | 01 (released on GM day 19) |
| **Lane** | 🌐 Web Exploitation |
| **Challenge ID** | `web-exploitation-day-01-backup-exposure` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/web/webrun.py`](../solvers/web/webrun.py) (`solve_backup`), legacy [`solvers/web/web01_backup.py`](../solvers/web/web01_backup.py) |

## Prompt
> The deploy left its diary behind. Somewhere out in the open, an old backup is still telling secrets — go find the archive this site forgot to clean up.

## TL;DR
The web lane has no downloadable artifact: a started attempt returns one or more **live target sites**, and the answer is a `proof_<32 hex>` string read out of the running app. This first challenge is classic **backup exposure** — an HTML comment hints at `robots.txt`, a `Disallow:` entry points at a forgotten directory, and that directory's index lists a `*.json.bak` backup containing the proof.

## Artifact
No file is delivered. Starting the attempt returns `targets[]`; each entry has a live `url` (single solve is root-mounted at `/`). The answer is submitted as `{answer_id: "proof-1"}` for single solve and `proof-1..N` for mastery (one per target). Every proof is the `exact_text` value `proof_<32 hex>`.

The target is a small static-looking status/uptime site (skins observed: "Back Up a Minute", "Status Sprout", "Tiny Uptime"). The crawl chain is:

| Step | Where | What it holds |
|---|---|---|
| 1 | homepage HTML comment | a hint toward `robots.txt` |
| 2 | `robots.txt` | `Disallow: /<random-dir>/` |
| 3 | `/<random-dir>/` index | links to `environment-copy-*.json.bak`, release notes |
| 4 | the `.json.bak` | `support_note` / similar field = `proof_…` |

## Solution
1. `GET /` and `GET /robots.txt`. Collect every `Disallow:` directory (the exact directory name is randomized per attempt).
2. Fetch each disallowed directory as a listing, parse all `href`s.
3. Fetch each linked file (prioritize `.bak`, `.json`, `.old`) and regex-search the body for `proof_`.

The generic version in `solve_backup` just walks robots `Disallow` dirs → parses `href`s → fetches each → searches for `proof_`, which is robust to the randomized directory and file names. No authentication or trickery is needed; the backup is simply world-readable.

## Time Trial & Mastery
Time Trial and Mastery were played **untimed** by sending `run_for_time:false` on the `/time_trial` and `/mastery` routes (regular play, no countdown). The single-solve route rejects `run_for_time` entirely, so it is omitted there. Mastery bundles **2 sets**; each set is its own target and may be a *different* challenge type, so the solver detects the type per target and maps one proof per target. No logic changes between modes — the same crawl solves every variant.

## Lessons / gotchas
- The web lane was the sixth, late-discovered lane; its mechanics (live targets, `proof_<hex>` answers, per-attempt randomization) are shared by all 31 challenges here — see [the lane overview](../lanes/web.md).
- Don't trust extensions: the backup is whatever file carries `proof_`, found by content, not by name.
- Keep to one provisioning path per challenge slot (bare API *or* browser arena, never both) — they share the single live-target slot and will expire each other's target.
