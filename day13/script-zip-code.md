# 📜 Zip Code

| | |
|---|---|
| **Day** | 13 |
| **Lane** | 📜 Script Analysis |
| **Challenge ID** | `script-analysis-day-13-archive-delivery-chain` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day13_script/s9.py`](../solvers/day13_script/s9.py) + [`sdec.py`](../solvers/day13_script/sdec.py) (unchanged copies of Day 12) · [`timed.py`](../solvers/day13_script/timed.py) |

## Prompt
> A delivery archive nests scripts inside containers inside more containers. Trace each member's role and handoff without executing a single one, and identify the link in the chain that was never supposed to be delivered.

## TL;DR
**913 questions** = the Day-12 contract (855, unchanged) + 58 new: four **AppleScript** polyglots and two
advanced Bash fixtures. There was no "never delivered" question. The Day-12 solver computed 913/913 with
no changes, and the lane took about 4 minutes.

## Artifact
WinZip-AES ZIP (`infected`). New files:

| File | Questions | Notes |
|---|---|---|
| `polyglot-applescript-{benign-utility,downloader,launcher,staged-chain}.applescript` | 4 × 11 | campaign `APPLESCRIPT-<8hex>` |
| `subshell-pipeline.sh` | 7 | feature `subshell_pipeline`, primitive `command_substitution_pipeline` |
| `process-substitution.sh` | 7 | feature `process_substitution`, primitive `process_substitution_reader` |

Both Bash fixtures: role `advanced_syntax`, attack `T1059.004`, stage count 1, steps
`recognize_syntax>reconstruct_intent`.

## Solution
1. `fetch.py <ch> <dir>` → `qdiff.py <day12 start.json> <day13 start.json>` → 0 gone, 0 changed, 58 new.
2. Run the Day-12 solver unchanged. The AppleScript files carry the standard `HUNTRESS_ANALYSIS_V1` header,
   and the regex found it without a language-specific pattern. All 11 answers come from the decoded
   descriptor, with the recorded role and attack ([Day 8](../day08/script-lost-in-translation.md)). The
   Bash fixtures decode through the generic Material/Codec path
   ([Day 9](../day09/script-all-the-world-s-a-stager.md)).
3. Single Solve: bank the six new files first
   (`--by-file --only "polyglot-applescript|bash-advanced-subshell|bash-advanced-process-subst"`: 4 × 11 + 2 × 7
   `accepted`), then the rest in 10-file batches, the last one CORRECT.

## Time Trial & Mastery
- Time Trial: 913 answers, window about 50 s, one-shot in 4.5 s with `timed.py`.
- Mastery: 1,826 answers (2 sets), window about 80 s, one-shot in 5.6 s. The default artifact bundled both
  sets. No rate limit was hit.

## Lessons / gotchas
- The archive-in-archive theme in the prompt was already handled by the loader: `s9.load()` recurses into
  nested per-set ZIPs.
- Five days in a row (Day 9 → 13), the lane appended one polyglot language plus, usually, two Bash
  fixtures: MOF → TypeScript → AutoIt → AppleScript.
- Previous: [Day 12](../day12/script-autoit-takes-two.md) · Next: [Day 14](../day14/script-trust-the-process.md).
