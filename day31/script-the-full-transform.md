# 📜 The Full Transform

| | |
|---|---|
| **Day** | 31 |
| **Lane** | 📜 Script Analysis |
| **Challenge ID** | `script-analysis-day-31-xslt-final-gauntlet` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day31_script/s23.py`](../solvers/day31_script/s23.py) (unchanged) · new helpers [`st31.py`](../solvers/day31_script/st31.py), [`adiff.py`](../solvers/day31_script/adiff.py), [`xsl_check.py`](../solvers/day31_script/xsl_check.py), [`wdiff2.py`](../solvers/day31_script/wdiff2.py), [`run_m.sh`](../solvers/day31_script/run_m.sh) |

## Prompt
> An unseen XSLT-led campaign ties together all thirty-one languages, every hosted-source profile, and every finding family you've proven. Read all of it, run none of it, and deliver the final analysis.

## TL;DR
The "final gauntlet" was the usual one-language delta: four **XSLT** stylesheets. Single Solve = Day-30
single + 44 (1,846); Time Trial = hash-named contract + 52 (1,950); Mastery **15 sets** × 1,950 = 29,250, the
largest submit of the event. The Day-23..30 `s23.py` stack computed every answer of all three modes on the
first try. The only extra work was defensive: a stricter wording diff, a check that nothing was reused from
yesterday, and a mastery driver that refuses to submit unless every answer is computed.

## Artifact
- Single Solve: `polyglot-xslt-{benign-utility,downloader,launcher,staged-chain}.xsl`, 11 questions each.
  Every `host-profile` answer is `standalone`.
- Time Trial / Mastery: hash-named (`polyglot-xslt-<6hex>-role`, …), 13 questions per stylesheet.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!-- HUNTRESS_ANALYSIS_V1:<HEADER>-<payload> -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/"><descriptor><same payload></descriptor></xsl:template>
</xsl:stylesheet>
```

Single Solve headers: `FRAG`, `HEX`, `B64`, `HB64`. Timed layered profiles seen: `b64_rev_hex`, `b32_hex`,
`hex_b32_rev`, `hex_hex_hex`. All go through `sdec.decode_specimen` (see [Day 23](../day23/script-press-start-to-decode.md)
for `LYR`).

## Solution
1. `st31.py` → `op=status` before start. It reports `start_required`, but still returns the name, prompt and
   the full question list.
2. `fetch.py` + `extract.py` → `qdiff <day30 single> <day31 single>` → 0 gone, 0 changed, 44 new →
   `s23.py --dir` → 1,846/1,846.
3. Extra checks this day:
   - `xsl_check.py`: confirms by regex that the comment header and the `<descriptor>` payload are byte-equal
     in all four stylesheets. The stylesheets were only read as text and never transformed.
   - `adiff.py`: compares answers with Day 30's. The single artifact was regenerated: 187 of 188 carried-over
     files had new bytes, and 455 of the 1,802 shared answers differed (campaign tokens, URLs, some adapters).
     Never reuse an earlier day's answers.
4. Recorded fields stay independent of each other, as on [Day 30](../day30/script-spill-the-beans.md)
   (`downloader` with `decode_configuration>return_configuration`, `dropper` with
   `build_schedule>dispatch_process`). The recorded values were accepted, including `attack` (`none`, `T1105`,
   `T1059`, `T1140`).
5. Single Solve: `--submit --by-file --only polyglot-xslt` (4 × `accepted`), then `--submit --exclude polyglot-xslt`
   → CORRECT. Submit output went to log files first (`s_bank.log`, …), so a broken pipe could not hide a
   verdict as it did on Day 30.

## Time Trial & Mastery
- **Contract check**: `wdiff <day30 tt> <day31 tt>` flagged 265 of 386 shapes as REWORDED. All came from one
  `exact_text` format hint: "exact artifact-derived value only, without quotes or explanatory text unless quotes
  are part of the value" became "Exact artifact-derived value only; no added quotes or explanation." The new
  `wdiff2.py` compares only question text, answer kind and accepted values, and found **0 real changes** across
  the 386 shared shapes, plus the 13 new XSLT shapes.
- Time Trial: untimed (`deadline: None`, `run_for_time: False`, 32 ranked attempts left). Bank the 4 XSLT groups
  (13 each), then the remaining 1,898 → CORRECT.
- Mastery via `run_m.sh`: a live `s23.py <ch>/mastery --save scr_m`, then a gate that **refuses to submit unless
  29,250/29,250 answers are computed**. Then it banks the XSLT groups (`--only polyglot-xslt --files 15`,
  4 batches of 195) and submits the remaining 28,470 only if the bank step reported no bad groups. All 15 sets
  were fetched and computed in 10.3 s with no diagnostics → CORRECT.
- All three verdicts were re-read with `confirm.py`.

## Lessons / gotchas
- A "final gauntlet" framing did not mean a format change. Run the same 2-second contract checks and trust
  them.
- Separate cosmetic rewording from real contract changes (`wdiff2.py`). A changed format hint inflated the
  diff to 265 "reworded" shapes with no semantic change.
- Gate big submits on a complete compute, and log before printing. Both cost nothing and remove the two
  failure modes seen late in the event.
- Previous: [Day 30](../day30/script-spill-the-beans.md) · Lane overview: [Script Analysis](../lanes/script.md).
