# 📜 Trust the Process

| | |
|---|---|
| **Day** | 14 |
| **Lane** | 📜 Script Analysis |
| **Challenge ID** | `script-analysis-day-14-msbuild-trusted-project-abuse` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day14_script/s9.py`](../solvers/day14_script/s9.py) + [`sdec.py`](../solvers/day14_script/sdec.py) (unchanged copies of Day 13) · [`timed.py`](../solvers/day14_script/timed.py) |

## Prompt
> An MSBuild project looks like routine build plumbing until you follow its properties into its targets. Recover the property and target flow, compare it with earlier execution chains, and find where a trusted toolchain is doing untrusted work.

## TL;DR
**971 questions** = the Day-13 contract (913, unchanged) + 58 new: four **MSBuild XML** polyglot projects
and two advanced Bash fixtures. No question asked about MSBuild property or target flow. The Day-13 solver
computed 971/971 unchanged in about 3 minutes.

## Artifact
WinZip-AES ZIP (`infected`). New files:

| File | Questions | Notes |
|---|---|---|
| `polyglot-msbuild_xml-{benign-utility,downloader,launcher,staged-chain}.proj` | 4 × 11 | campaign `MSBUILD_XML-<8hex>` |
| `getopts-state.sh` | 7 | feature `getopts_state`, primitive `option_parser_state` |
| `brace-expansion.sh` | 7 | feature `brace_expansion`, primitive `cartesian_brace_expansion` |

Bash fixtures: role `advanced_syntax`, attack `T1059.004`, stage count 1, steps
`recognize_syntax>reconstruct_intent`, campaign `BASHX-<8HEX>`.

## Solution
1. `fetch.py <ch> <dir>` → `qdiff.py <day13 start.json> <day14 start.json>` → 0 gone, 0 changed, 58 new.
2. The `.proj` files carry the `HUNTRESS_ANALYSIS_V1` header in an XML context, and the generic decoder in
   `sdec.py` handled them with no change. All 11 answers come from the descriptor
   ([Day 8](../day08/script-lost-in-translation.md)):
   - benign-utility → role `benign_utility`, attack `none`, **even though its recorded steps are
     `decode_embedded>write_file>dispatch_process`**;
   - downloader → `T1105`;
   - launcher and staged-chain → the recorded attack **`T1059`** (the parent technique, not a
     language-specific sub-technique).
3. Single Solve: bank the six new files first
   (`--by-file --only "polyglot-msbuild|bash-advanced-getopts|bash-advanced-brace-exp"`), then the rest in
   10-file batches, the last one CORRECT.

## Time Trial & Mastery
- Time Trial: 971 answers, 30-second window, one-shot in 2.4 s (`timed.py`).
- Mastery: 1,942 answers (2 sets), 30-second window, one-shot in 3.0 s. The default artifact bundled both
  sets. No rate limit was hit.

## Lessons / gotchas
- For polyglots, the recorded `attack` beats any per-language table. Here it is the bare parent technique
  `T1059`, while the Day 2–7 language files use `T1059.00x` sub-techniques.
- Recorded role and steps can contradict each other (benign role, dropper-looking steps). Answer each field
  from its own recorded value.
- Previous: [Day 13](../day13/script-zip-code.md) · Next: [Day 15](../day15/script-crumb-trail.md).
