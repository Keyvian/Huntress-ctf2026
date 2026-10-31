# 👶 Room Forty-Seven

| | |
|---|---|
| **Day** | 15 |
| **Lane** | 👶 Warmups |
| **Challenge ID** | `warmups-day-15` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day15_quick/warm15.py`](../solvers/day15_quick/warm15.py) |

## Prompt
> Even the punctuation went for a spin.

## TL;DR
ROT47: every printable character from `!` (33) to `~` (126) is rotated by 47 in that 94-character range. Spaces are left
alone. Unlike ROT13, digits and punctuation rotate too ("even the punctuation"). ROT47 is its own inverse.
`warm15.py` = `warm14.py` + a `rot47` layer and an `r47` row codec.

## Artifact
- Single Solve and Time Trial: one ROT47 line.
- Mastery: 73 sets of mixed-codec blobs (15 rows; row 15 = ROT47). HTML-entity rows and the others were unchanged.

## Solution
```python
def rot47(s):
    return "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in s)
```
Added to `layers()` (whole blob) and `line_decode_l()` (label `r47`). Per-position learning
([Day 13](../day13/warmups-opposite-day.md)) ranked it correctly for row 15.

## Time Trial & Mastery
Single CORRECT. Time Trial CORRECT (~1.6 s). Mastery CORRECT for all 73 sets (~1.8 s). Each mode used one process:
start, fetch, decode, submit.

## Lessons / gotchas
- ROT47 maps letters and digits to punctuation-heavy text, so the output of ROT47 on an unrelated row is obvious
  garbage. On short slug fragments, though, it can still compete. That came back to bite on
  [Day 26](../day26/warmups-food-for-thought.md), when ROT47 of a framed Ascii85 row out-scored the real decode.
