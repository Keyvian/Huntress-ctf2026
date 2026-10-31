# 👶 Little Things

| | |
|---|---|
| **Day** | 19 |
| **Lane** | 👶 Warmups |
| **Challenge ID** | `warmups-day-19` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day19_quick/warm19.py`](../solvers/day19_quick/warm19.py) |

## Prompt
> Two bytes walk into a bar. The little one goes first.

## TL;DR
Hex of **UTF-16LE** text with a byte-order mark: `fffe 4e00 6900 6300 …` = BOM `FF FE`, then `N\0i\0c\0…`. Two bytes per
character, low byte first ("the little one goes first"). Unhexlify, drop the BOM, then decode as `utf-16-le`.

## Artifact
- Single Solve and Time Trial: `blob.txt`, one hex string starting `fffe`.
- Mastery: 93 sets (`blob-01.txt`…`blob-93.txt`), 19 mixed-codec rows each. Row 19 is UTF-16LE hex carrying the slug
  tail (e.g. `19\tfffe70006c0065002d…`).

## Solution
`warm19.py` adds `u16()`, applied to **every byte-producing decode** (hex, Base64, Base32 output in `layers()`, the raw
blob in `solve_blob()`, and every row candidate, which then gets a `<codec>16` label such as `hex16`):

```python
def u16(b):
    if b[:2] == b"\xff\xfe": return b[2:].decode("utf-16-le")
    if b[:2] == b"\xfe\xff": return b[2:].decode("utf-16-be")
    if len(b) % 2 == 0:                       # BOM-less: alternating zero bytes give away the order
        if all(b[i] == 0 for i in range(1, len(b), 2)) and all(b[i] for i in range(0, len(b), 2)):
            return b.decode("utf-16-le")
        if all(b[i] == 0 for i in range(0, len(b), 2)) and all(b[i] for i in range(1, len(b), 2)):
            return b.decode("utf-16-be")
    return None
```
It also handles big-endian, so [Day 20](../day20/warmups-big-entrance.md) needed no new decoder.

## Time Trial & Mastery
All timed modes came up as regular untimed attempts (`deadline: None`). Time Trial was CORRECT. Mastery was CORRECT for
all 93 sets, with 2.8 s of compute. Some middle rows were ranked wrongly (letter soup won), but the template regex on the
final `Game Master: <slug>` line still produced the right slug for every blob.

## Lessons / gotchas
- Treat an encoding of bytes (UTF-16) as a post-processing step on every byte decoder, not as one more codec. It can wrap
  hex, Base64, Base32, and later gzip output as well.
- When middle rows go wrong but the slug comes out right, that is luck, not robustness. The next day it fell apart
  ([Day 20](../day20/warmups-big-entrance.md)).
