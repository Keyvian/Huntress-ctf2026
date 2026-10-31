# 📜 Fetch Quest

| | |
|---|---|
| **Day** | 17 |
| **Lane** | 📜 Script Analysis |
| **Challenge ID** | `script-analysis-day-17-download-graph` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day17_script/s9.py`](../solvers/day17_script/s9.py) + [`sdec.py`](../solvers/day17_script/sdec.py) (unchanged copies of Day 16) · [`timed.py`](../solvers/day17_script/timed.py) |

## Prompt
> The source code says where it would fetch from, and the generated network evidence says where the requests actually went. Reconcile both into one download graph, and find the indicator that shows up on only one side of the story.

## TL;DR
**1,139 questions** = the Day-16 contract (1,095, unchanged) + 44 new: four **AutoHotkey v2** polyglots. The
artifact contained no network evidence at all, only the 127 script fixtures. The Day-16 solver computed
1,139/1,139 unchanged.

## Artifact
WinZip-AES ZIP (`infected`), 127 fixtures. New: `polyglot-auto_hotkey-{benign-utility,downloader,launcher,staged-chain}.ahk`,
11 questions each:

```autohotkey
; HUNTRESS_ANALYSIS_V1:<ENC>-<payload>
descriptor_<hex> := "<same payload>"
```
A `buildPlan_<hex>()` function then returns `Map("descriptor", …)` around that string.

Encodings seen: `B64`, `HB64`, `FRAG`, `HEX`. Campaign IDs look like `AUTO_HOTKEY-<8hex>`, and
`host_profile` is `standalone`. No host fixture and no Bash fixtures this day, the first such day since Day 10.

## Solution
1. `fetch.py` + `extract.py` → `qdiff.py <day16> <day17>` → 0 gone, 0 changed, 44 new.
2. `s9.py <ch> --dir <dir> --show auto_hotkey` → 1,139/1,139, none unanswered. The `;` comment header decodes
   with the standard decoder ([Day 8](../day08/script-lost-in-translation.md)), and every answer is a
   recorded descriptor field (benign-utility → `none`, launcher/staged-chain → `T1059`, downloader → `T1105`).
3. Single Solve: AutoHotkey groups banked first (4 × 11 `accepted`), then 10-file batches, the last one CORRECT.

The syntax-true Batch expansion rule was accepted again in all three modes.

## Time Trial & Mastery
- Time Trial: regular attempt with `deadline: None` (the catalog lists a 50 s ranked deadline and a 30 s
  solve budget for opt-in timed runs). One full submit in 3.7 s → CORRECT.
- Mastery: 5,695 answers (5 sets) from one 572 KB default artifact, one full submit in 7.3 s → CORRECT.

## Lessons / gotchas
- Nine days in a row, the prompt's forensic story (here a source-vs-network reconciliation) had no matching
  question. Check the artifact listing before planning for evidence that is not there.
- Previous: [Day 16](../day16/script-same-same-but-different.md) · Next: [Day 18](../day18/script-orphan-process.md).
