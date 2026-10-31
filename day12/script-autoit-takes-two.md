# 📜 AutoIt Takes Two

| | |
|---|---|
| **Day** | 12 |
| **Lane** | 📜 Script Analysis |
| **Challenge ID** | `script-analysis-day-12-autoit-workflow-pair` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day12_script/s9.py`](../solvers/day12_script/s9.py) + [`sdec.py`](../solvers/day12_script/sdec.py) (unchanged) · [`timed.py`](../solvers/day12_script/timed.py) (backoff) · [`qdiff.py`](../solvers/day12_script/qdiff.py) |

## Prompt
> Two inert AutoIt workflows arrived as a matched set, and each one carries half the story. Correlate them with everything you've proven so far, and decide which pairing is genuine and which is just going through the motions.

## TL;DR
**855 questions** = the Day-11 contract (811) + 44 new: four **AutoIt** polyglots. No "pairing" question
existed. The interesting change was that **192 existing questions were reworded** to spell out the grading
rubric (and their answer formats listed more accepted values), yet **no answer changed**. The Day-11 solver
answered all 855 unchanged in about 3 minutes.

## Artifact
WinZip-AES ZIP (`infected`), a 99-file `evidence.zip`. New: `polyglot-autoit-{benign-utility,downloader,launcher,staged-chain}.au3`,
11 questions each. Shape:

```autoit
; HUNTRESS_ANALYSIS_V1:B64-<payload>
Global Const $descriptor_<hex> = "<same payload>"
```

Campaign IDs look like `AUTOIT-<8hex>`.

## Solution
1. `fetch.py <ch> <dir>`, then `qdiff.py <day11 start.json> <day12 start.json>` → **0 gone, 44 new,
   192 reworded**.
2. The generic `ANALYSIS` regex has no comment-syntax anchor, so AutoIt's `;` comment and the
   `Global Const` string both matched. All 11 AutoIt answers come from the decoded descriptor (recorded
   role/attack; benign-utility → `none`).
3. The rewording made the rubric explicit for questions that had been graded the same way all along:
   role/attack precedence, the JScript property-style scope, Batch expansion/control, the VBScript transform
   family, and the PowerShell collection technique, now described as a "browser credential store"
   (`T1555.003`, with `T1005` also accepted). Answer formats now listed values such as `relay` and
   `persistence_descriptor` in the role enum. The Day-11 outputs were all graded CORRECT, which confirmed that
   the rewording was cosmetic.
4. Single Solve: bank the new files first (`s9.py … --submit --by-file --only polyglot-autoit`, 4 × 11
   `accepted`), then `--by-file --files 10 --exclude polyglot-autoit`. All batches `accepted`, the last one CORRECT.

## Time Trial & Mastery
- `timed.py` now wraps `start`/`artifact` in a `call()` helper that backs off on `rate_limited` (three agents
  share one GM token). No rate limit was actually hit.
- Time Trial: 855 answers, 30-second window, one-shot in 2.4 s.
- Mastery: 1,710 answers (2 sets), 30-second window, one-shot in 2.7 s. The default artifact bundled both sets.

## Lessons / gotchas
- Reworded questions are not necessarily new answers. Diff the IDs and the wording separately, and test the
  old answers before rewriting a classifier.
- Bank the day's new files first. If they are wrong, you find out from an 11-answer group instead of a
  failed 855-answer submit.
- Previous: [Day 11](../day11/script-by-any-other-name.md) · Next: [Day 13](../day13/script-zip-code.md).
