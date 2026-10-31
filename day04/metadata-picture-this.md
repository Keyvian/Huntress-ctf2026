# 🔎 Picture This

| | |
|---|---|
| **Day** | 04 |
| **Lane** | 🔎 Metadata Forensics |
| **Challenge ID** | `metadata-forensics-day-04-picture-this` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/solve_picture_all.py`](../solvers/solve_picture_all.py) |

## Prompt
> A dozen photographs have been resized, renamed, and shuffled. Reconstruct their true dimensions and find the image whose presentation does not match its structure.

## TL;DR
The new field is `jpeg.sof_dimensions_pixels`: the frame size stored in the JPEG Start-Of-Frame marker, answered
`<width>x<height>`. SOF stores height before width, so the order must be swapped. `camera-001.jpg` gave `257x146`.
That format was CORRECT on the first untimed probe, and one solver then cleared all three modes on its first attempt.

## Artifact
- Single Solve: answer id `d04-jpeg-001-jpeg-sof-dimensions-pixels`, "Determine jpeg.sof_dimensions_pixels for
  camera-001.jpg.", artifact `metadata-day-04-evidence.zip -> camera-001.jpg` (a baseline JPEG; the same 257x146
  `camera-001.jpg`, 3,025 bytes, is reused in the cumulative bundles of Days 8–9).
- Format: `exact_text`, "exact artifact-derived value only, without quotes or explanatory text unless quotes are part
  of the value; use the literal none only when the requested field is absent". The same wording is used for every
  scalar field in this lane.
- Time Trial: one JPEG. Mastery: two sets (one JPEG each, nested per-set ZIPs).

## Solution
Walk the JPEG marker stream from `FF D8`, skip standalone markers, jump over every other segment by its 2-byte
big-endian length, and stop at the first SOF marker. SOF markers are `FFC0`–`FFCF` except `C4` (DHT), `C8` (JPG
extension) and `CC` (DAC). Inside the SOF segment: length (2), precision (1), **height (2)**, **width (2)**.

```python
def sof(data):
    if data[:2] != b"\xff\xd8": return None
    i, n = 2, len(data)
    while i + 1 < n:
        if data[i] != 0xFF: i += 1; continue
        m = data[i + 1]
        if m in (0xD8, 0xD9, 0x01, 0xFF) or 0xD0 <= m <= 0xD7:
            i += 1 if m == 0xFF else 2; continue
        ln = struct.unpack(">H", data[i + 2:i + 4])[0]
        if 0xC0 <= m <= 0xCF and m not in (0xC4, 0xC8, 0xCC):
            h, w = struct.unpack(">HH", data[i + 5:i + 9])
            return w, h                      # answer f"{w}x{h}"
        i += 2 + ln
    return None                              # -> "none"
```

For `camera-001.jpg` the SOF0 segment holds height `0x0092` (146) and width `0x0101` (257), so the answer is
`257x146`. The single solve probed this format first and it was CORRECT.

## Time Trial & Mastery
`solve_picture_all.py` runs both timed modes in one process each: start (or retry), fetch the default artifact,
recursively extract it, map each question to its JPEG, answer, submit. Questions are mapped by the basename after
`->`. If that member is missing, the fallback is the set index over the extracted `.jpg` members (set *k* → *k*-th
JPEG). Time Trial and Mastery were each CORRECT on the first attempt.

If a target has no SOF marker the solver answers `none`, the format's "field absent" literal. No such disguised
non-JPEG is recorded in the solve logs.

## Lessons / gotchas
- The answer is width first, the reverse of the byte order in the SOF segment.
- Don't stop at the first `FFCx`. `FFC4` is a Huffman table that appears before the frame header in many files.
- The prompt's story (resized, shuffled, "presentation does not match its structure", i.e. EXIF orientation) never
  became a question. This happens on almost every day of this lane: the prompt describes an investigation, but the
  grader asks for one exact header field.
- `jpeg.sof_dimensions_pixels` enters the cumulative contract as `d04-jpeg-001-…` (`camera-001.jpg`) from
  [Day 8](../day08/metadata-whats-in-the-box.md) onward.
