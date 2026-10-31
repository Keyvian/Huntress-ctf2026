# 📜 Sharp Practice

| | |
|---|---|
| **Day** | 19 |
| **Lane** | 📜 Script Analysis |
| **Challenge ID** | `script-analysis-day-19-managed-assembly-bridge` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day19_script/sdec.py`](../solvers/day19_script/sdec.py) (header regex fix) + [`s9.py`](../solvers/day19_script/s9.py) · [`timed.py`](../solvers/day19_script/timed.py) |

## Prompt
> A Roslyn C# script and an inline ASPX host act as a bridge that carries managed code back into the script corpus. Recover their layered configuration, resolve each static handoff, and work out where the bridge actually leads.

## TL;DR
**1,249 questions** = the Day-18 contract (1,194, unchanged) + 55 new: four **C# script** (`.csx`)
polyglots and one ASPX host fixture that embeds a whole `.csx` specimen as a C# string literal. No assembly
or DLL was in the artifact. The only fix was a one-character regex change: the header payload must stop at a
backslash, because inside the string literal it is followed by a literal `\n`.

## Artifact
WinZip-AES ZIP (`infected`), 137 fixtures. New files:

| File | Questions | Notes |
|---|---|---|
| `polyglot-csharp_script-{benign-utility,downloader,launcher,staged-chain}.csx` | 4 × 11 | header, then `#nullable enable`, `string descriptor_<hex> = "…"`, `BuildPlan_<hex>()` returning a `Dictionary<string,string>` |
| `host-aspx-inline-csharp-csharp-script.csx` | 11 | ASPX page (`<%@ Page Language="C#" %>` + `<script runat="server">`) holding `EmbeddedCsx_<hex> = "// HUNTRESS_ANALYSIS_V1:HEX-<payload>\n#nullable enable\n…"` |

Header encodings seen: `HB64`, `HEX`, `B64`, `FRAG`.

## Solution
1. `fetch.py` + `extract.py` → `qdiff.py <day18> <day19>` → 0 gone, 0 changed, 55 new.
2. `s9.py --show csharp` → only the 11 ASPX-host questions were unanswered. The four `.csx` polyglots
   decoded with the standard header path ([Day 8](../day08/script-lost-in-translation.md)).
3. The bug: the payload part of the header regex was `[^\s"'<>\]]+`. In the ASPX host, the header sits inside
   a C# string literal and is followed by the two characters `\` `n` rather than a real newline, so the regex
   swallowed `\n#nullable…` into the hex payload and the decode failed. The fix also stops at a backslash:

```python
# before (Day 8–18)
ANALYSIS = re.compile(r"HUNTRESS_ANALYSIS_V1:([A-Z0-9]+)-([^\s\"'<>\]]+)")
# after (Day 19 on)
ANALYSIS = re.compile(r"HUNTRESS_ANALYSIS_V1:([A-Z0-9]+)-([^\s\"'<>\]\\]+)")
```

4. The host descriptor then decoded to `host_profile=aspx_inline_csharp`, role `staged_chain`, attack
   `T1059`, obfuscation `plain_hex`, stage profile `single_descriptor`, next language `jscript`, steps
   `decode_configuration>return_configuration`, campaign `CSHARP_SCRIPT-<8hex>`. All were accepted as
   recorded, the same as the Day-18 host.
5. Single Solve: the C# groups banked first (`--only csharp`, 5 × 11 `accepted`), then 10-file batches, the
   last one CORRECT.

The Day-18 SPLIT path stayed in place, unused this day.

## Time Trial & Mastery
- Time Trial: regular attempt (`deadline: None`), one full submit in 4.5 s → CORRECT.
- Mastery: 6,245 answers (5 sets) from a 621 KB default artifact, one full submit in 7.2 s → CORRECT.
- Syntax-true Batch expansion accepted again. No rate limiting.

## Lessons / gotchas
- Host fixtures can embed the entire specimen as an escaped string. Keep header regexes tolerant of escape
  sequences and quoting. Possible future variants include verbatim `@"…"` strings, raw strings and
  concatenated literals.
- A small "unanswered" count after the first compute pinpoints the new packaging. `--show <regex>` plus
  reading one raw file is usually enough.
- Previous: [Day 18](../day18/script-orphan-process.md) · Next: [Day 20](../day20/script-the-butler-did-it.md).
