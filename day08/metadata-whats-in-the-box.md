# 🔎 What’s in the Box?

| | |
|---|---|
| **Day** | 08 |
| **Lane** | 🔎 Metadata Forensics |
| **Challenge ID** | `metadata-forensics-day-08-whats-in-the-box` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | One-off `d8meta.py` (not preserved). The same logic, plus Day 9, is [`solvers/day09/m9.py`](../solvers/day09/m9.py) |

## Prompt
> The count was only the beginning. Inventory every stored path, preserve directory context, and identify the archive whose names reveal an impossible provenance claim.

## TL;DR
Day 8 turns the lane into a **compounding contract**. Every mode asks the 7-question evidence-note block from Days 1–3
plus one question for each file type from Days 4–7, plus the new field `zip.central_directory_member_names`: a compact
JSON array of the names stored in the central directory of `evidence-drop-001.zip`, directory prefixes included. All
the extractors were already written, so the work was assembling them and adding a central-directory walker.

## Artifact
`metadata-day-08-evidence.zip` (3,308 bytes, plain ZIP) with five members:

| Member | Size | Used by |
|---|---|---|
| `evidence-note.txt` | 33 | filename, size, MD5, SHA-1, SHA-256, `magic-prefix-hex-16`, `text.utf8_bom_present` |
| `camera-001.jpg` | 3,025 | `d04-jpeg-001-jpeg-sof-dimensions-pixels` (`257x146`) |
| `panel-001.png` | 414 | `d05-png-001-png-ihdr-dimensions-pixels` (`269x153`) |
| `document-001.pdf` | 1,552 | `d06-pdf-001-pdf-header-version` (`1.4`) |
| `evidence-drop-001.zip` | 410 | `d07-zip-001-zip-eocd-total-entries` (`2`) and **`d07-zip-001-zip-central-directory-member-names`** |

That makes 12 questions per set. The new question is `json`-kind: "compact valid JSON array with exact values and
order; no Markdown or explanatory text". Its id keeps the `d07-zip-001` prefix because it reads the Day-7 artifact.
Time Trial is the same 12 questions on a fresh variant. Mastery is **5 sets × 12 = 60** questions.

## Solution
Walk the central directory from the EOCD and emit the stored names in record order:

```python
def zip_cd_names(b):
    e = b.rfind(b"PK\x05\x06")
    n, cdsz, cdoff = struct.unpack("<HII", b[e + 10:e + 20])   # total entries, CD size, CD offset
    names, p = [], cdoff
    for _ in range(n):
        if b[p:p + 4] != b"PK\x01\x02": break
        fl, el, cl = struct.unpack("<HHH", b[p + 28:p + 34])   # name / extra / comment lengths
        names.append(b[p + 46:p + 46 + fl].decode("utf-8", "replace"))
        p += 46 + fl + el + cl
    return json.dumps(names, separators=(",", ":"))
```

Answer for the delivered drop: `["room-01/item-1.txt","room-02/item-1.txt"]`. The "preserve directory context" in the
prompt means the stored path with its `room-NN/` prefix, not the basename. Use compact JSON with no spaces.

The other eleven answers come from the earlier extractors: [Day 1](../day01/metadata-you-must-be-this-hash-to-ride.md)
digests, [Day 2](../day02/metadata-looks-can-be-deceiving.md) prefix hex,
[Day 3](../day03/metadata-bom-voyage.md) BOM, [Day 4](../day04/metadata-picture-this.md) SOF,
[Day 5](../day05/metadata-chunk-norris.md) IHDR, [Day 6](../day06/metadata-portable-deception.md) PDF header and
[Day 7](../day07/metadata-seven-zip-no-relation.md) EOCD count.

## Time Trial & Mastery
- Single Solve had been solved before the session that handled the timed modes. A later pipeline test recomputed all
  12 single-solve answers from the real bytes in well under a second (the GM answered `already_solved`).
- Time Trial (12 q) and Mastery (60 q, one nested `evidence-0K.zip` per set) were each CORRECT on the first submit of
  `d8meta.py`.
- Mastery sets are nested ZIPs inside the default artifact, the same layout as Days 1–7.

## Lessons / gotchas
- Once the lane compounds, an old field that silently breaks fails the whole submit. A table of field-name →
  extractor (`FIELDS` in `m9.py`) that every later solver extends worked better than per-day rewrites.
- Note for later days: [Day 23](../day23/metadata-page-me-maybe.md) found that the grader compares this array
  **sorted**. File order passed here only because the drop's names were already in lexicographic order.
- The "impossible provenance claim" in the prompt never became a question.
