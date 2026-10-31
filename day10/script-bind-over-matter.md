# 📜 Bind Over Matter

| | |
|---|---|
| **Day** | 10 |
| **Lane** | 📜 Script Analysis |
| **Challenge ID** | `script-analysis-day-10-wmi-persistence-reconstruction` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day10_script/s9.py`](../solvers/day10_script/s9.py) + [`sdec.py`](../solvers/day10_script/sdec.py) (Day-9 solver, unchanged) · [`timed.py`](../solvers/day10_script/timed.py) · [`qdiff.py`](../solvers/day10_script/qdiff.py) |

## Prompt
> A MOF file declares classes, namespaces, filters, and consumers, but only some bindings actually tie them together. Reconstruct the persistence intent, separate the operational relationships from the decoys, and name the subscription that would really survive a reboot.

## TL;DR
The prompt promises WMI event-subscription analysis, but the question set was the **Day-9 contract
(695 questions, same wording and artifacts) plus 58 new questions**, **753** in total. The new questions
were four WMI MOF polyglots carrying the usual `HUNTRESS_ANALYSIS_V1` header and two advanced Bash
fixtures. No question asked about filters, consumers or bindings. The Day-9 solver answered all 753
without a code change. This day set the routine for the next two weeks: diff the question IDs against
yesterday, run yesterday's solver, submit.

## Artifact
WinZip-AES ZIP (`infected`), one 89-file `evidence.zip`. New files:

| File | Questions | Notes |
|---|---|---|
| `polyglot-wmi_mof-{benign-utility,downloader,launcher,staged-chain}.mof` | 4 × 11 | header + `instance of HuntressAnalysis_<hex> { Descriptor = "…"; }` |
| `heredoc-reconstruction.sh` | 7 | feature `heredoc_reconstruction`, primitive `quoted_heredoc` |
| `here-string.sh` | 7 | feature `here_string`, primitive `here_string_read` |

The two Bash fixtures use a percent-hex material (`Codec='percent_hex|'`).

## Solution
1. **Diff the contract.** `qdiff.py <day9 start.json> <day10 start.json>` → 0 gone, 0 changed, 58 new IDs.
   (`start.json` is the saved `op=start` response with every question's id, text, artifact and format.)
2. **Run the previous solver.** The MOF files use `//` comments, which the existing `ANALYSIS` regex already
   matches. Each MOF repeats the same payload as a `Descriptor` property on an `instance of` block. Decoding
   the header gives the usual `v=3|…` descriptor (see [Day 8](../day08/script-lost-in-translation.md)), and
   all 11 answers come from it.
3. **Use recorded role and attack.** The benign-utility MOF has dropper-like steps, but its graded role is
   the recorded `benign_utility` with attack `none`.
   Do not reclassify from the steps.
4. The Bash fixtures went through the generic Material/Codec brute-forcer. `nums_from()` already understands
   `%HH` sequences, so `percent_hex` needed no change. Answers: role `advanced_syntax`, attack `T1059.004`,
   feature/primitive/campaign/stage count/steps from the plan.
5. Single Solve: `s9.py <ch> --dir <dir> --submit --by-file --files 10` (10-file batches with bisection on
   failure). All 9 batches came back `accepted`, and the last one returned CORRECT.

Since the real MOF subscription structure (`__EventFilter`, consumer, `__FilterToConsumerBinding`) was never
asked in any mode, no MOF semantic parsing was needed.

## Time Trial & Mastery
- New helper `timed.py <challenge> <dir>`: one process does start → default artifact (fetching extra
  deliveries in parallel only if a set is missing) → compute → **one full submit**. If the full submit is
  `incorrect`, it falls back to banking per-file groups in parallel and prints the wrong groups.
- Time Trial: 753 answers in a 13-second window, solved in 2.1 s.
- Mastery: 1,506 answers (2 sets) in a 32-second window, solved in 2.8 s. The default artifact already
  contained both sets; `load()` maps nested ZIPs or `artifact_dK.bin` files to set numbers.

## Lessons / gotchas
- When a day's question set is a superset of the previous day's, diff the IDs first. The old solver may
  already be complete.
- The prompt is flavor text. Read the actual questions before building anything the prompt suggests.
- Previous: [Day 9](../day09/script-all-the-world-s-a-stager.md) · Next: [Day 11](../day11/script-by-any-other-name.md).
