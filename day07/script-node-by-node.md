# 📜 Node by Node

| | |
|---|---|
| **Day** | 07 |
| **Lane** | 📜 Script Analysis |
| **Challenge ID** | `script-analysis-day-07-node-operation-graphs` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | The Day-7 solver (`d7script_solve.py`, Homebase VM) was not preserved; its rules live on in [`solvers/day09/s9.py`](../solvers/day09/s9.py) (`ID_ROLE`, `attack_for`) |

## Prompt
> Eight Node.js operation graphs that will never execute. Spot the indirect expansions and token fragmentation, then sort each graph into its role — benign, staging, dropping, downloading, uploading, launching, scheduled, or multi-stage — from the final bytes alone.

## TL;DR
The Day-6 set (399 questions) plus eight Node.js `.mjs` operation graphs and the first two "advanced syntax"
Bash fixtures, **469 questions**. The `.mjs` files follow the Bash pattern exactly: a Material/Codec pair
(Base64 + `reverse_bytes`) that decodes to a `v=1|…` plan, with the same 7 questions. The two new ideas were a
`persistence_descriptor` role mapped to cron (`T1053.003`) and a new Bash question family, `feature` and
`primitive`, that names the shell feature being demonstrated.

## Artifact
WinZip-AES ZIP (`infected`): everything from [Day 6](../day06/script-shell-we-begin.md) plus

| File | Role | Notes |
|---|---|---|
| `node-context.mjs` | `benign_utility` | |
| `node-memory-stage.mjs` | `stager` | |
| `node-embedded-write.mjs` | `dropper` | |
| `node-remote-write.mjs` | `downloader` | |
| `node-outbound-transfer.mjs` | `uploader` | |
| `node-local-dispatch.mjs` | `launcher` | |
| `node-schedule-descriptor.mjs` | `persistence_descriptor` | indicator `schedule-path` |
| `node-staged-chain.mjs` | `staged_chain` | indicator includes a `service-name` |
| `indirect-expansion.sh` | `advanced_syntax` | feature `indirect_expansion`, primitive `parameter_indirection` |
| `token-fragmentation.sh` | `advanced_syntax` | feature `token_fragmentation`, primitive `array_token_construction` |

Node questions (7): `role`, `attack`, `adapter`, `campaign`, indicator, `stage-count`, `steps`. Advanced Bash
questions (7): `role`, `attack`, `feature`, `primitive`, `campaign`, `stage-count`, `steps`. Answer IDs are
prefixed `nodejs-<role>-…` and `bash-advanced-<name>-…`.

## Solution
**Node `.mjs`.** Each module holds a Base64 material plus a `reverse_bytes` codec and an inspect path guarded
by `HUNTRESS_INSPECT_ONLY`. On this day the solver ran the fixtures' own inspect path
(`HUNTRESS_INSPECT_ONLY=1 node file.mjs`) in parallel subprocesses to print the plan. From
[Day 9](../day09/script-all-the-world-s-a-stager.md) on, the static Material/Codec brute-forcer recovered the
same plan without running anything.

- `role`: from the id hint (`nodejs-benign`, `-stager`, `-dropper`, `-downloader`, `-uploader`,
  `-launcher`, `-persistence`, `-chain`).
- `attack`: the lane table, with Node's execution technique **`T1059.007`** (JavaScript) for launcher and
  staged_chain, and **`T1053.003`** (Scheduled Task/Job: Cron) for the `persistence_descriptor` schedule
  file.
- indicator: the plan key named by the id tail (`url`, `host-id`, `file-path`, `schedule-path`,
  `service-name`, …). The later solver generalizes this as "the longest id tail that names a plan key".
- `stage-count` and `steps` as on Day 6 (steps joined with `>`).

**Advanced Bash.** These are Bash fixtures whose plan describes a shell feature rather than a behavior. Role
is always `advanced_syntax`, attack `T1059.004`, and `feature`/`primitive` are read from the plan. The
`steps` value for this family was `recognize_syntax>reconstruct_intent` with a stage count of 1 (as recorded
on later days, when two more fixtures were added each day).

## Time Trial & Mastery
- The Day-6 parallel-submit approach carried over unchanged for Time Trial (about 40 answers per chunk, enum
  candidates as parallel single submits).
- Mastery delivered the two sets as nested `evidence-0K.zip` members of the default artifact, under a
  **13-second** deadline. The `.mjs`/`.sh` subprocess decoding was parallelized to fit.
- Two GM mechanics surfaced this day:
  - `start` often returns the previous, expired attempt (no `answer_ids`). `retry` gives a fresh ranked
    attempt; `op=practice` gives an unranked attempt with **no deadline**, so no mode is ever truly blocked.
  - Answers must be JSON **strings**. An integer `stage-count` sent as a number returns
    `error: invalid_answers`.

## Lessons / gotchas
- New roles arrive with new languages. `persistence_descriptor` → `T1053.003` joined the role/attack table
  and stayed for the rest of the event.
- The advanced-syntax Bash family became a recurring add-on. Two new fixtures were added on nine days
  between Day 7 and Day 20, each with its own `feature`/`primitive` pair.
- Previous: [Day 6](../day06/script-shell-we-begin.md) · Next: [Day 8](../day08/script-lost-in-translation.md).
