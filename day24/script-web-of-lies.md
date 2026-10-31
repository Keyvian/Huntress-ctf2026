# 📜 Web of Lies

| | |
|---|---|
| **Day** | 24 |
| **Lane** | 📜 Script Analysis |
| **Challenge ID** | `script-analysis-day-24-jsp-webshell-source` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day24_script/s23.py`](../solvers/day24_script/s23.py) (verbatim copy of Day 23) · [`lyr.py`](../solvers/day24_script/lyr.py) · [`qdiff.py`](../solvers/day24_script/qdiff.py) / [`wdiff.py`](../solvers/day24_script/wdiff.py) · [`confirm.py`](../solvers/day24_script/confirm.py) |

## Prompt
> This JSP source is shaped like a webshell: it reads requests and stages server-side work. Recover the order of requests and stages, then separate the inert fixture behavior from the lines that would be real execution primitives in the wild.

## TL;DR
A JSP polyglot family and nothing else. Single Solve = the Day-23 single contract + 55 questions (4 JSP
polyglots + a JSP webshell host). Time Trial and Mastery = the Day-23 **timed** contract + 65 questions (13 per
hash-named `.jsp`). The Day-23 `s23.py` stack answered every question of all three modes on the first
compute, and the whole lane took about 5 minutes. Mastery grew from 7 to **8 sets**.

## Artifact
- Single Solve (1,516 questions): `polyglot-jsp-{benign-utility,downloader,launcher,staged-chain}.jsp` and
  `host-jsp-webshell-jsp.jsp`, 11 questions each.
- Time Trial (1,560) / Mastery (8 × 1,560 = 12,480): the same five specimens under hash names, with the
  13 timed-contract questions each: `role`, `attack`, `steps`, `stage-count`, `stage-profile`, `obfuscation`,
  `next-language`, `campaign`, `url`, `file-path`, `url-host`, `path-leaf`, `campaign-token`.

Carrier shape:

```jsp
<%-- HUNTRESS_ANALYSIS_V1:<HEADER>-<payload> --%>
<%@ page contentType="text/plain" %>
<%! private static final String DESCRIPTOR_<HEX> = "<same payload>"; %>
<%= "inert-analysis-fixture" %>
```

Headers: `B64`, `HEX`, `HB64`, `FRAG` in the Single Solve variant. The timed variants use the Day-23
`LYR-<chain>` form (`b32_rev_b64`, `b32_rev_b32`, `b32_b32_frag`, `b64_frag_hex`, …).

## Solution
1. `fetch.py` + `extract.py` (162 files) → `qdiff.py <day23 single> <day24 single>` → 55 new, all JSP.
   `s23.py --dir` → 1,516/1,516 with no diagnostics.
2. The only special wording is the host question: "Identify the script host or **webshell source
   container**". The answer is the descriptor's `host_profile=jsp_webshell`; polyglots say `standalone`.
   Everything else is the recorded descriptor field ([Day 8](../day08/script-lost-in-translation.md)), and
   the timed-only fields (`url-host`, `path-leaf`, `campaign-token`, `obfuscation` = LYR chain) follow
   [Day 23](../day23/script-press-start-to-decode.md).
3. The `<%-- Modeled request surface only; no command execution. --%>` trailer in the webshell host is a
   decoy, not an answer source. No question asks about requests, execution primitives or inert-vs-real lines.
   A regex over all three `start.json` files matched only the older Python `carrier|windows_chain` questions.
4. The timed descriptors record arbitrary role/attack pairs (e.g. role `persistence_descriptor` with attack
   `T1053` and steps ending in `dispatch_memory`). The grader wants the **recorded** values.
5. Single Solve: `s23.py --submit --by-file --only jsp` (5 groups `accepted`), then `--submit --exclude jsp`
   → CORRECT.

## Time Trial & Mastery
- Time Trial: `fetch.py` (untimed, `run_for_time: False`, 32 unique attempts), then
  `wdiff.py <day23 tt start.json> <day24 tt start.json>` → only the 13 JSP shapes new, 0 gone, 0 reworded.
  Same bank-then-rest submit → CORRECT.
- Mastery: `s23.py <ch>/mastery --save <dir>` (no submit). Start took 1.6 s, all 8 sets were loaded from the
  single default ZIP by 4.1 s, and 12,480/12,480 answers were computed by 4.8 s. Then a cached
  `--submit --by-file --only jsp --files 8` (5 × 104 `accepted`) and `--submit --exclude jsp` → CORRECT.
- Verdicts re-read with `confirm.py` (`op=status`).

## Lessons / gotchas
- Expected pattern from here on: single = previous single + 11 per new file; timed = previous timed + 13 per
  new file. Verify with `qdiff` (single) and `wdiff` (timed). If both show only the new language and
  `s23.py --dir` reports no diagnostics, bank the new groups and submit the rest in one request.
- Keep running `wdiff` every day. It is the 2-second check that would catch another Day-23-style rewrite.
- Previous: [Day 23](../day23/script-press-start-to-decode.md) · Next: [Day 25](../day25/script-ashes-to-assets.md).
