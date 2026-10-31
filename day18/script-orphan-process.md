# 📜 Orphan Process

| | |
|---|---|
| **Day** | 18 |
| **Lane** | 📜 Script Analysis |
| **Challenge ID** | `script-analysis-day-18-process-story` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day18_script/sdec.py`](../solvers/day18_script/sdec.py) (new `split_header()`) + [`s9.py`](../solvers/day18_script/s9.py) · [`timed.py`](../solvers/day18_script/timed.py) |

## Prompt
> Source code describes which process should spawn which, and native telemetry keeps its own record of events. Reconstruct the static process tree, and catch the child claiming a parent it never had.

## TL;DR
**1,194 questions** = the Day-17 contract (1,139, unchanged) + 55 new: four **Google Apps Script** polyglots
and a Google Docs sidebar host fixture. There was no telemetry file and no process-tree question. This was
the first day the header **packaging** changed: the `.gs` files split the analysis payload across a
JavaScript string array. A 10-line `split_header()` reassembles it, and everything downstream worked unchanged.

## Artifact
WinZip-AES ZIP (`infected`), 132 fixtures. New files:

| File | Questions | Notes |
|---|---|---|
| `polyglot-google_apps_script-{benign-utility,downloader,launcher,staged-chain}.gs` | 4 × 11 | campaign `GOOGLE_APPS_SCRIPT-<8hex>` |
| `host-google-docs-sidebar-google-apps-script.gs` | 11 | `host_profile=google_docs_sidebar`, role `staged_chain`, attack `T1059`; decorative `DocumentApp.getUi().createMenu("Document Tools")` sidebar with a fake "Decrypt document" panel |

## Solution
### The SPLIT header
Instead of a one-line `HUNTRESS_ANALYSIS_V1:<ENC>-<payload>` comment, the `.gs` files carry:

```javascript
// HUNTRESS_ANALYSIS_V1:SPLIT
const HUNTRESS_ANALYSIS_V1_SPLIT_<8hex> = ["<ENC>-<frag>", "<frag>", "<frag>", …].join("");
// … plus buildAnalysisPlan_<8hex>(), which returns Object.freeze({ descriptor: <payload without the ENC- prefix> })
```

Concatenate the quoted strings in array order to get `<ENC>-<payload>`, then decode exactly as before
([Day 8](../day08/script-lost-in-translation.md)). Encodings seen: `FRAG`, `HB64`, `HEX`, `B64`. With
`FRAG`, the dots fall anywhere, including mid-byte and across array elements, so strip all non-hex
characters after joining and only then call `bytes.fromhex`.

```python
SPLIT_ARRAY = re.compile(r"HUNTRESS_ANALYSIS_V1_SPLIT_\w+\s*=\s*\[(.*?)\]", re.S)

def split_header(text):
    if "HUNTRESS_ANALYSIS_V1:SPLIT" not in text:
        return None
    m = SPLIT_ARRAY.search(text)
    if not m:
        return None
    parts = re.findall(r"\"([^\"]*)\"|'([^']*)'", m.group(1))
    joined = "".join(a if a else b for a, b in parts)
    return joined if re.match(r"[A-Z0-9]+-", joined) else None
```

`decode_specimen()` calls `split_header()` first. After that, the `polyglot-` and `host-` id prefixes route
every answer to the decoded descriptor as usual (recorded role/attack, `host_profile`, `obfuscation_profile`, …).

### Steps
1. `fetch.py` + `extract.py` → `qdiff.py <day17> <day18>` → 0 gone, 0 changed, 55 new.
2. `s9.py --show "google|docs"` showed 55 unanswered → inspected a `.gs` file → added `split_header()` →
   1,194/1,194 computed statically.
3. Single Solve: the five new groups banked first (`--only "google|docs"`), then 10-file batches, the last
   one CORRECT.

## Time Trial & Mastery
- Time Trial: regular attempt (`deadline: None`), one full submit in 3.6 s → CORRECT.
- Mastery: 5,970 answers (5 sets) from a 604 KB default artifact, one full submit in 7.2 s → CORRECT.
- The syntax-true Batch expansion default was accepted again. No rate limiting.

## Lessons / gotchas
- Expect the packaging to change as well as the language: split arrays, string literals, layered encodings.
  Reassemble generically (collect every quoted fragment in order) instead of matching one exact form.
- Previous: [Day 17](../day17/script-fetch-quest.md) · Next: [Day 19](../day19/script-sharp-practice.md).
