# 📜 Hatch Careful

| | |
|---|---|
| **Day** | 05 |
| **Lane** | 📜 Script Analysis |
| **Challenge ID** | `script-analysis-day-05-python-carrier-lab` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | The Day-5 solver (`unified_solve.py`, on the Homebase VM) was not preserved; its logic was folded into [`solvers/day09/s9.py`](../solvers/day09/s9.py) + [`sdec.py`](../solvers/day09/sdec.py) |

## Prompt
> Nine Python behaviors come wrapped in fourteen disguises: bytecode, wheels, zipapps, frozen executables, and armored runtimes. Peel each carrier back to its intent without letting anything hatch, and identify the package that tells a different story than its payload.

## TL;DR
The Day-4 set (PowerShell + JScript + Batch + VBScript, 231 questions) plus **14 "recovered" Python
carriers** with 9 questions each, **357 questions** in total. Every Python file is a self-describing inert
fixture. Its `MATERIAL_<id>`/`CODEC_<id>` decode to a `v=2|…` plan that directly records seven of the nine
answers, including four carrier-profile labels. Role and ATT&CK come from a small steps→role table. The real
challenge was the timed modes: about 7 seconds for 357 or 714 answers, with no banking across attempts. That
forced a parallel-submit strategy.

## Artifact
WinZip-AES ZIP (`infected`) with the 30 earlier specimens plus 14 Python files, each standing in for a
different packaging "disguise":

`source-context.py`, `pyc38-recovered.py`, `current-pyc-recovered.py`, `zipapp-recovered.py`,
`wheel-recovered.py`, `pyinstaller-onefile-recovered.py`, `pyinstaller-onedir-recovered.py`,
`py2exe-console-recovered.py`, `py2exe-service-recovered.py`, `cxfreeze-recovered.py`,
`cxfreeze-msi-recovered.py`, `pyarmor-source-recovered.py`, `pyarmor-pyinstaller-recovered.py`,
`embedded-runtime-recovered.py`.

Python questions (9 per file): `role`, `attack`, `adapter`, `campaign`, an indicator (`url`, `host-id`,
`file-path`, …), `syntax`, `obfuscation`, `carrier`, `windows-chain`.

## Solution
### Python carriers
Each carrier defines `MATERIAL_<id>` (decimal CSV), `CODEC_<id>` and small `decode_/recover_/surface_/plan_`
functions that do nothing but byte arithmetic. `surface_<id>()` returns the 4-tuple
`(syntax, obfuscation, carrier, windows_chain)`, and `recover_<id>()` returns the plan, for example:

```
v=2|steps=locate_local,dispatch_process|adapter=interpreter_argv|stage_count=1|syntax=closure_factory|
obfuscation=chr_join|carrier=hash_based_pyc_current|windows_chain=pythonw_hidden_console|
campaign_id=campaign-<10 hex>|file_path=C:/…
```

On Day 5 the decode functions were evaluated in an isolated namespace, and only the `recover_` routine was
called. From [Day 9](../day09/script-all-the-world-s-a-stager.md) on, the same plans were recovered fully
statically by brute-forcing the Material/Codec pair.

Values recorded on this day show the four label families:

| Field | Examples |
|---|---|
| `syntax` | `class_staticmethod`, `closure_factory`, `iterator_protocol`, `dictionary_dispatch`, `walrus_binding`, `match_case`, `lambda_dispatch`, `decorator_wrapper` |
| `obfuscation` | `chr_join`, `reflective_name_plan`, `marshal_envelope_plan`, `reversed_fragments`, `lambda_indirection`, `exception_routing`, `closure_cells`, `bytes_translation` |
| `carrier` | `hash_based_pyc_current`, `zipapp_pyz`, `pyinstaller_onedir`, `py2exe_console`, `py2exe_windows_service`, `cx_freeze_executable`, `cx_freeze_msi`, `pyarmor_pyinstaller`, `embeddable_python_runtime` |
| `windows-chain` | `pythonw_hidden_console`, `renamed_interpreter`, `run_key_descriptor`, `service_descriptor`, `scheduled_task_descriptor`, `rundll32_predecessor`, `regsvr32_predecessor`, `powershell_to_python`, `cmd_to_python` |

Seven answers are read straight from the plan: adapter, campaign (`campaign_id`), indicator, and the four labels.
**Role** comes from the ordered `steps` (the "nine behaviors"):

| Steps (set) | Role |
|---|---|
| `decode_configuration, return_configuration` | `benign_utility` |
| `acquire_remote, dispatch_memory` / `dispatch_pipe` | `stager` |
| `decode_embedded, write_file` | `dropper` |
| `acquire_remote, write_file` | `downloader` |
| contains `transmit_remote` / `upload_remote` | `uploader` |
| `locate_local, dispatch_process` | `launcher` |
| contains `write_recovery_note` / `transform_copy` | `impact` |
| `decode_configuration, locate_interpreter, dispatch_next_stage` | `relay` |
| `handoff_script` or ≥ 4 steps | `staged_chain` |

Unlike JScript, Batch and VBScript, the Python `relay` files are graded as **`relay`**. **ATT&CK** uses the
lane table with **`T1059.006`** (Python) for launcher, staged_chain and relay.

The prompt's "package that tells a different story than its payload" never became a separate question in the
recorded contract. Each carrier answers its own `carrier`/`windows-chain` labels.

### Carried-over languages
Unchanged from [Day 4](../day04/script-dim-and-dimmer.md): PowerShell Base64 JSON, JScript plan reconstruction
plus syntax styles, Batch `set`-fragment plan plus expansion/control/graph, VBScript Material/Codec plus
control. VBScript gained a `reverse_then_xor` transform in this generation.

## Time Trial & Mastery
This day changed the timed-mode strategy:
- Each `start` produced fresh questions with a deadline of **about 7 seconds**, and banked answers did
  **not** carry over to the next attempt. All 357 (Time Trial) or 714 (Mastery, `set1.`/`set2.`) answers had
  to land in a single attempt.
- One huge submit was not an option: the GM rejected submits above roughly 40–50 long answers (60 failed).
- Winning pattern, all in one process with a thread pool:
  1. decode the live artifact (Mastery: fetch `delivery=0` and `delivery=1` in parallel threads);
  2. submit the deterministic answers in **chunks of ~40** in parallel;
  3. for every variant-dependent enum (Batch `expansion`/`control`), submit **every candidate label as its
     own single-answer submit** in parallel. The right one banks and the wrong ones are harmless.
- Time Trial finished in about 2.4 s. Mastery used CHUNK=40 and about 90 parallel jobs and finished in about
  4.1 s, both under the 7-second deadline.
- On Single Solve, `collection-attack` was accepted as `T1005` (Day 1 had accepted `T1555.003`).

## Lessons / gotchas
- The per-submit payload size limit and concurrency-triggered rate limiting were the real constraints on big
  timed modes. Tune chunk size and worker count, not the solver.
- A full submit returns only CORRECT or `incorrect`; it never returns `remaining`. A submit that finishes the
  challenge returns the flag instead of a count, so do not treat a missing `remaining` as a failure.
- Python `relay` is graded `relay`, while the Windows-host languages map relay to `staged_chain`. Keep role
  rules per language.
- Previous: [Day 4](../day04/script-dim-and-dimmer.md) · Next: [Day 6](../day06/script-shell-we-begin.md).
