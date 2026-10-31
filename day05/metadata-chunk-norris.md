# 🔎 Chunk Norris

| | |
|---|---|
| **Day** | 05 |
| **Lane** | 🔎 Metadata Forensics |
| **Challenge ID** | `metadata-forensics-day-05-chunk-norris` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | One-off scripts (not preserved). The same extractor is `png_ihdr()` in [`solvers/day09/m9.py`](../solvers/day09/m9.py) |

## Prompt
> The PNGs render, but rendering is not proof. Walk their chunks, verify their declared geometry, and locate the image with an unexpected structural passenger.

## TL;DR
The new field is `png.ihdr_dimensions_pixels`: the width and height declared in the PNG `IHDR` chunk, answered
`WxH`. The value is two big-endian integers at byte offsets 16–24. Both timed modes tripped over labels. The question
named one panel, but the attempt delivered another. The fix was to measure the PNG actually delivered, and in mastery
to map sets by the nested ZIP rather than by the panel name.

## Artifact
- Single Solve: `d05-png-001-png-ihdr-dimensions-pixels`, "Determine png.ihdr_dimensions_pixels for
  panel-001.png.", artifact `metadata-day-05-evidence.zip -> panel-001.png` (414 bytes). Format: `exact_text` with the
  usual `none`-if-absent rule.
- A chunk walk of `panel-001.png` showed a clean file: `IHDR` (13 bytes, 269×153, bit depth 8, colour type 2),
  one `IDAT`, `IEND`, all CRCs valid, nothing after `IEND`.
- Time Trial: one question (`d05-png-002-…` for `panel-002.png`); the ZIP holds a single PNG.
- Mastery: two questions, `set1.d05-png-003-…` → `metadata-day-05-evidence-01.zip -> panel-003.png` and
  `set2.d05-png-004-…` → `metadata-day-05-evidence-02.zip -> panel-004.png`. The default artifact is an outer ZIP that
  contains both per-set ZIPs; `delivery=1` returns `{"error":"invalid_delivery"}`.

## Solution
```python
def png_ihdr(b):
    if b[:8] != b"\x89PNG\r\n\x1a\n" or b[12:16] != b"IHDR":
        return "none"
    w, h = struct.unpack(">II", b[16:24])
    return "%dx%d" % (w, h)
```
The first chunk always starts at offset 8: length (4), type `IHDR` (4), then width and height. The single solve
`269x153` was CORRECT. A full chunk walker (length, type, CRC-32 over type+data, trailing bytes after `IEND`) was also
written for the "structural passenger" story, but no question used it.

## Time Trial & Mastery
- **Time Trial:** the first submits answered `none`. The question named `panel-002.png`, but the ZIP fetched during
  that attempt contained `panel-005.png`. (One extra bug was a `requests.get` without the shared session.) With one
  PNG per ZIP, the panel label carries no information, so the final version simply measured the single delivered PNG
  and was CORRECT (`282x162`).
- **Mastery:** answers computed from the per-delivery fetches were `incorrect`. The nested ZIPs held `panel-006.png` and
  `panel-007.png` while the questions said 003/004, so a basename match found nothing (`none`, incorrect again). The
  working mapping uses the left side of the `->` label: `set1` → the PNG inside `metadata-day-05-evidence-01.zip`,
  `set2` → the one inside `-02.zip`, with set order as fallback. CORRECT in 1.6 s.

## Lessons / gotchas
- Panel numbers in labels can be cosmetic. When a container holds exactly one candidate of the right type, measure
  that candidate. When sets are nested ZIPs, key on the container name, not the inner filename.
- Mastery timers this day were a few seconds (about 7 s). A whole attempt has to run in one process.
- `png.ihdr_dimensions_pixels` joins the cumulative contract as `d05-png-001-…` (`panel-001.png`) from
  [Day 8](../day08/metadata-whats-in-the-box.md) onward.
