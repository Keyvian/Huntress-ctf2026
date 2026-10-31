# 📜 Make It Make Sense

| | |
|---|---|
| **Day** | 29 |
| **Lane** | 📜 Script Analysis |
| **Challenge ID** | `script-analysis-day-29-makefile-variant-diff` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day29_script/s23.py`](../solvers/day29_script/s23.py) (verbatim copy of Day 28) · [`qdiff.py`](../solvers/day29_script/qdiff.py) · [`wdiff.py`](../solvers/day29_script/wdiff.py) |

## Prompt
> Unseen Makefile variants and their prior-language build chains differ in layered variables and target flow. Diff them carefully, and keep only the tradecraft conclusions that hold up across every variant.

## TL;DR
Four **Makefile** polyglots. Single Solve = Day-28 single + 44 (1,747); Time Trial = the hash-named contract
(1,833); Mastery 13 sets × 1,833 = 23,829. Zero solver changes, no diagnostics, about 5 minutes.

## Artifact
`polyglot-makefile-{benign-utility,downloader,launcher,staged-chain}.mk`, 11 questions each in Single Solve.
The timed IDs look like `polyglot-makefile-<6hex>-*`, 13 per file.

```makefile
# HUNTRESS_ANALYSIS_V1:<HEADER>-<payload>
HUNTRESS_DESCRIPTOR_<HEX> := <same payload>
.PHONY: analyze-<hex>
analyze-<hex>:
	@:
```

Single Solve headers included `HB64`. Timed obfuscation profiles seen: `b32_hex_b32`, `b32_b32`,
`hex_b64_hex`, `hex_hex_b64`. All are handled by `sdec.decode_specimen` and its `LYR` branch
([Day 23](../day23/script-press-start-to-decode.md)). Payload: the usual
`v=3|language=makefile|…|campaign_id=MAKEFILE-<8hex>|url=https://makefile-<10hex>.example.invalid/stage|file_path=/tmp/huntress-makefile/.<16hex>.stage`.

## Solution
1. `op=status` before start → `scr_status0.json` (1,747 questions).
2. `fetch.py` + `extract.py` → `qdiff <day28 single> <day29 single>` → 44 new → `s23.py --dir` → 1,747/1,747.
3. Recorded `attack` accepted: downloader `T1105`, launcher/staged-chain `T1059`, benign `none`. On Time Trial
   the variants also recorded stager → `T1105` and `persistence_descriptor` → `T1053`.
4. "Diff the variants / keep only conclusions that hold across every variant" never became a question.
   Each specimen is answered from its own descriptor.
5. Single Solve: `--submit --by-file --only makefile` (4 × `accepted`), then `--submit --exclude makefile` → CORRECT.

## Time Trial & Mastery
- Time Trial: `qdiff` against today's single → 0 common, so `wdiff <day28 tt> <day29 tt>` → 13 new shapes
  (Makefile × 13, including `url-host`, `path-leaf`, `campaign-token`), 0 gone, 0 reworded. Untimed
  (`deadline: None`, 32 unique attempts). Bank the 4 Makefile groups (13 each), then the remaining 1,781 → CORRECT.
- Mastery: `s23.py <ch>/mastery --save <dir>` → 13 sets by 7.6 s, 23,829 answers computed by 9.2 s.
  Cached `--submit --by-file --only makefile --files 13` (4 groups of 169), then the remaining 23,153 → CORRECT.
  No rate limiting.

## Lessons / gotchas
- This was the sixth day in a row of the same delta (one language, +11 single / +13 timed per file). When the
  two contract checks (`qdiff` on single, `wdiff` on timed) show only the new language and `s23.py --dir`
  reports no diagnostics, the rest is mechanical.
- The prompt's "unseen variants" are just the regenerated per-mode artifacts. Always compute from the
  freshly downloaded bytes.
- Previous: [Day 28](../day28/script-out-of-order.md) · Next: [Day 30](../day30/script-spill-the-beans.md).
