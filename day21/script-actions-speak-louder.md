# 📜 Actions Speak Louder

| | |
|---|---|
| **Day** | 21 |
| **Lane** | 📜 Script Analysis |
| **Challenge ID** | `script-analysis-day-21-github-actions-persistence` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day21_script/s9.py`](../solvers/day21_script/s9.py) + [`sdec.py`](../solvers/day21_script/sdec.py) (unchanged copies of Day 20) · [`timed.py`](../solvers/day21_script/timed.py) |

## Prompt
> A GitHub Actions workflow decides who can trigger it and which runner inherits the trust. Identify each trigger and trust boundary, follow the static handoff into the next language, and find the job that keeps coming back.

## TL;DR
**1,373 questions** = the Day-20 contract (1,329, unchanged) + 44 new: four **GitHub Actions workflow**
polyglots (`.yml`). No trigger, trust-boundary or persistence question existed. The workflows only park the
usual analysis descriptor in a job environment variable. The Day-20 solver computed 1,373/1,373 with no
changes. No lane note was written for this day, so this writeup is reconstructed from the agent transcript;
see the caveat under Time Trial & Mastery.

## Artifact
WinZip-AES ZIP (`infected`), 149 files, 148 of them referenced by questions. The unreferenced extra is
`invoke-python-stage.ps1`, a PowerShell → Python precursor that has been in the archive since at least Day 9.
It is probably the kind of file behind the cross-file `handoff-id` question that appears on
[Day 23](../day23/script-press-start-to-decode.md). New: `polyglot-github_actions-{benign-utility,downloader,launcher,staged-chain}.yml`,
11 questions each.

```yaml
# HUNTRESS_ANALYSIS_V1:B64-dj0zfGxhbmd1YWdlPWdpdGh1Yl9hY3Rpb25z…
name: Huntress inert analysis <8hex>
on:
  workflow_dispatch:
jobs:
  analyze:
    runs-on: ubuntu-latest
    env:
      HUNTRESS_DESCRIPTOR: "<same payload>"
    steps:
      - name: Preserve modeled descriptor
        run: ':'
```

Each file used a different header encoding: benign-utility `B64`, downloader `HB64`, launcher `FRAG`,
staged-chain `HEX`.

## Solution
1. `fetch.py` + `extract.py` → `qdiff.py <day20 start.json> <day21 start.json>` → old 1,329, new 1,373,
   all 1,329 common, 44 new IDs.
2. The YAML `#` comment header decodes with the standard path ([Day 8](../day08/script-lost-in-translation.md)).
   For example, the benign-utility workflow decodes to
   `v=3|language=github_actions|role=benign_utility|verdict=benign|attack=none|adapter=local_parser|host_profile=standalone|obfuscation_profile=base64|stage_profile=two_stage_download_execute|next_language=powershell|stage_count=2|steps=acquire_remote,dispatch_process|campaign_id=GITHUB_ACTIONS-<8hex>|…`.
   Note the "benign" role recorded next to download-and-execute steps. As every day since Day 8, the grader
   wants the recorded role, not one re-derived from the steps.
3. Recorded values on the Single Solve attempt (per-attempt values elided):

| File | role / attack | adapter | obfuscation | stage profile / count | next language |
|---|---|---|---|---|---|
| benign-utility | `benign_utility` / `none` | `local_parser` | `base64` | `two_stage_download_execute` / 2 | `powershell` |
| downloader | `downloader` / `T1105` | `http_client` | `hex_base64` | (recorded) | (recorded) |
| launcher | `launcher` / `T1059` | `process_builder` | `fragmented_hex` | `cross_language_handoff` / 3 | (recorded) |
| staged-chain | `staged_chain` / `T1059` | `operation_graph` | `plain_hex` | `single_descriptor` / 2 | `vbscript` |

4. Single Solve: the four YAML groups banked first (`--by-file --only github`: 4 × 11 `accepted`), then the
   rest in 10-file batches. The final group returned CORRECT.

## Time Trial & Mastery
- Catalog values: Time Trial ranked deadline 90 s; Mastery 5 sets with a 170 s ranked deadline. Since Day 15,
  regular attempts start untimed unless `run_for_time` is requested.
- The agent ran the usual one-process `timed.py <ch>/time_trial` and then `timed.py <ch>/mastery`. The
  morning's automated run was interrupted at that point, and **no timing or verdict output for the timed modes
  survives in the logs or notes**. Both modes are recorded as solved, and the next day's run used the Day-21
  solvers and contract as its baseline, but how many attempts or seconds they took is not recorded.

## Lessons / gotchas
- Configuration-as-code formats (CI workflows, and later Dockerfiles, Terraform, Makefiles) are just another
  comment syntax for the header, plus a string field that repeats the payload.
- Write the per-day note before starting long timed runs. This day's interruption left the timed-mode
  details unrecorded.
- Previous: [Day 20](../day20/script-the-butler-did-it.md) · Next: [Day 22](../day22/script-next-next-finish.md).
