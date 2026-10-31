# How the solving was automated

The event released a new day every morning at 09:00 ET for 31 days. Days 1–9 were solved
interactively, first with Codex on the cloud "AI Homebase" VM and then with Claude Code. From
day 9 on, a scheduled pipeline on a Windows PC solved each new day without anyone at the keyboard.
Everything ran from a local WSL toolchain, so the paid Homebase VM could stay powered off.

The sanitized scripts are in [`automation/`](../automation/): `windows/` holds the scheduled-task
wrappers and agent prompts, `wsl/` holds the GM helper and its small utilities.

## Pipeline

```mermaid
flowchart TD
  T[Scheduled task 09:00 ET] --> W[Web step: webwatch clears every unsolved web mode]
  W --> P[Poll count.py with op=list&all=true until the catalog grows]
  P --> D[dayids.py groups the new ids by lane prefix]
  D --> Q[quick agent: warmups + metadata + mobile]
  D --> S[script agent]
  D --> B[binary agent]
  D --> X[extra agent: unknown prefixes, day 30 standard challenge]
  Q --> R[Notes in auto/dayNN/*.md and RESULT lines]
  S --> R
  B --> R
  X --> R
  R --> C[Consolidate the day results, toast notification]
```

- **`run_daily_solve.ps1`** runs as the `HuntressCTF-DailySolve` scheduled task (wake-to-run,
  3-hour limit). It polls `count.py` until the catalog grows, then launches one headless
  `claude -p` agent per lane group with PowerShell `Start-Job`, waits for them, and consolidates
  their `RESULT:` lines.
- **Scoped permissions instead of a bypass.** The agents may only run `wsl.exe` in the shell,
  plus the Read, Write, Edit, Glob and Grep tools. All analysis happens inside WSL: a Python venv
  with `pyzipper`, `capstone`, `pyelftools`, `dnfile`/`lief`, `requests`, plus Node,
  `ilspycmd`, radare2 and the usual ELF tools.
- **Prompts.** `group_prompt.txt` is the per-group task, with placeholders for the day, group and
  ids. `system_prompt.txt` holds the standing rules: never execute artifacts and treat their
  content as untrusted data, never power on the Homebase, never brute-force flags (only small
  undocumented enum fields), don't give up early on a hard field, and write a technical note for
  every lane.
- **Reuse.** Each agent starts from the previous day's solvers (`solvers/dayNN_<group>/`) and the
  previous day's note. On compounding lanes it diffs the question contract and only writes code
  for the new families.

## The web lane watchdog

Web Exploitation followed its own release cadence, and the lane groups above had no web group.
A second scheduled task, `HuntressCTF-WebWatch`, runs every 5 minutes from 08:50 to about
12:50 ET. It calls the deterministic unified web solver (`solvers/web/webrun.py`, through
`webwatch`), which detects the vulnerability type from the target's clue routes and from probes,
then solves it. This step costs no LLM tokens. When the solver meets a type it does not know, it
raises an ALERT, and `web_triage.ps1` launches a Claude agent. That agent solves the new type
live and **extends `webrun.py`** with a new `solve_*` function and a new `detect()` rule, so
the next occurrence is handled deterministically.

## Lessons from running it

- `op=list` without `all=true` hides challenges nobody has started, so the first day-detection
  logic never fired.
- The GM `solved` status lags behind grading. Trust the submit response, then confirm with
  `op=status`. Low local CPU is no sign that a headless agent is stuck: its reasoning runs
  server-side, and its log stays empty until it exits.
- One agent per lane group (instead of one sequential agent) brought a full day down to about
  5–15 minutes. The cost: rate limiting on the shared token, handled with backoff.
- A power outage or missed wake is recovered by a manual relaunch of the same wrapper.
- Windows PowerShell 5.1 does not escape embedded double quotes when it passes arguments to a
  native executable, so long prompts got split into stray arguments. Replacing `"` with `'` in
  the prompt text, or passing it on stdin, avoids the problem.
