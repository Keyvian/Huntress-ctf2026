# 📜 Spill the Beans

| | |
|---|---|
| **Day** | 30 |
| **Lane** | 📜 Script Analysis |
| **Challenge ID** | `script-analysis-day-30-beanshell-jsp-graph` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day30_script/s23.py`](../solvers/day30_script/s23.py) (verbatim copy of Day 29) · [`confirm.py`](../solvers/day30_script/confirm.py) · [`qdiff.py`](../solvers/day30_script/qdiff.py) / [`wdiff.py`](../solvers/day30_script/wdiff.py) |

## Prompt
> BeanShell source sits inside an inert JSP host container, and it's the last piece of a thirty-language puzzle. Analyze both, then rebuild the complete execution, host, and evidence graph, and find the edge that holds everything together.

## TL;DR
Four **BeanShell** polyglots and a JSP host that embeds BeanShell source as a Java string constant. Single
Solve = Day-29 single + 55 (1,802); Time Trial = hash-named contract + 65 (1,898); Mastery 14 sets × 1,898 =
26,572. Zero solver changes, no diagnostics, about 5 minutes. The "graph" and "edge that holds everything
together" never became questions.

## Artifact
- Single Solve: `polyglot-beanshell-{benign-utility,downloader,launcher,staged-chain}.bsh` and
  `host-jsp-beanshell-beanshell.bsh`, 11 questions each.
- Time Trial / Mastery: hash-named versions (IDs such as `powershell-<6hex>-url` for the composite
  PowerShell files), 13 questions per polyglot.

Standalone `.bsh`:

```java
// HUNTRESS_ANALYSIS_V1:<HEADER>-<payload>
String descriptor_<hex> = "<same payload>";
Map buildPlan_<hex>() {
  Map plan = new HashMap();
  plan.put("descriptor", descriptor_<hex>);
  return plan;
}
```

JSP host (`.bsh` name, JSP bytes). The whole BeanShell source is an inert Java string:

```jsp
<%@ page contentType="text/plain" %><%@ page import="bsh.Interpreter" %>
<%!
private static final String INERT_BEANSHELL_<HEX> = "// HUNTRESS_ANALYSIS_V1:FRAG-...\nString descriptor_<hex> = \"...\";\n…";
%><%= "inert-analysis-fixture" %>
```

The header inside the string literal is followed by a literal `\n`. That is exactly the case fixed on
[Day 19](../day19/script-sharp-practice.md) (the header regex stops at a backslash), so it decoded with no
change. Headers seen: `HB64`, `FRAG` (on two files, including the host), `HEX`, `B64`.

## Solution
1. `op=status` before start → `start_required`, but the response still carries the name, prompt and question
   count.
2. `fetch.py` + `extract.py` → `qdiff <day29 single> <day30 single>` → 55 new → `s23.py --dir` → 1,802/1,802.
3. The host question ("Identify the script host or webshell source container") answers the recorded
   `host_profile=jsp_beanshell`; the four polyglots answer `standalone`.
4. Recorded role, adapter and steps are independent per file and do not have to agree with each other
   (`downloader` with `profile_host>decode_configuration>dispatch_language`, `benign_utility` with
   `decode_embedded>write_file>dispatch_process`). The recorded values were accepted as-is, including
   `attack` (`none`, `T1105`, `T1059`).
5. Single Solve: `--submit --by-file --only beanshell` (5 × `accepted`), then `--submit --exclude beanshell`.

## Time Trial & Mastery
- Time Trial: `qdiff` against today's single → 0 common; `wdiff <day29 tt> <day30 tt>` → 13 new shapes
  (BeanShell × 13, n = 5 each), 0 gone, 0 reworded. Untimed (`deadline: None`). Bank the BeanShell groups,
  then the remaining 1,833 → CORRECT.
- Mastery: `s23.py <ch>/mastery --save <dir>` → 14 sets by 7.4 s, 26,572 answers computed by 9.1 s. Cached
  `--submit --by-file --only beanshell --files 14` (5 groups of 182), then the remaining 25,662 → CORRECT.
- The Single Solve verdict line did not show up in the output of a long chained shell command (a
  `qdiff | head` broken pipe in the same chain was suspected). The verdict was read back with `confirm.py`
  (`op=status`) instead of resubmitting.

## Lessons / gotchas
- When a verdict is not visible, confirm it with `op=status`. Do not resubmit blindly.
- Write submit output to a log file first and inspect the log, so a broken pipe cannot hide the result (this
  was adopted on [Day 31](../day31/script-the-full-transform.md)).
- Previous: [Day 29](../day29/script-make-it-make-sense.md) · Next: [Day 31](../day31/script-the-full-transform.md).
