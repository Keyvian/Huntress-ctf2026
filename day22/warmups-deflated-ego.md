# 👶 Deflated Ego

| | |
|---|---|
| **Day** | 22 |
| **Lane** | 👶 Warmups |
| **Challenge ID** | `warmups-day-22` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day22_quick/warm21.py`](../solvers/day22_quick/warm21.py) (the Day-21 solver, unchanged) |

## Prompt
> Another familiar wrapper. This one needs a little inflation.

## TL;DR
Base64 of a **zlib** stream (`eNo…` → `78 DA`, zlib with best compression). Base64-decode, then `zlib.decompress`. Day 21's
`inflate()` already recognized the zlib header bytes (`78 01/5E/9C/DA`), so `warm21.py` solved every mode without a code
change.

## Artifact
- Single Solve and Time Trial: `blob.txt`, one Base64 line starting `eNo`.
- Mastery: 108 sets (`blob-01.txt`…`blob-108.txt`), the 21 earlier codec rows plus a zlib row (row 22).

## Solution
```python
raw = base64.b64decode(blob)            # b"\x78\xda..."
text = zlib.decompress(raw).decode()    # "Nice work decoding this warmup! … Game Master: <slug>"
```
In the solver, a zlib header in any byte candidate (whole blob or row) triggers `inflate()`, and the result continues
through the same UTF-16 check and template search as on [Day 21](../day21/warmups-under-pressure.md).

## Time Trial & Mastery
All modes were regular untimed attempts. Time Trial was CORRECT (256 unique attempts available). Mastery was CORRECT for
all 108 sets, with 1.9 s of compute. The printed message looked cut off ("…g this warmup!"), but only the display slice
was. The submitted value comes from the slug regex.

## Lessons / gotchas
- Raw deflate (`wbits=-15`) does **not** decode this blob. It has the zlib header. Keep header-less guesses out of the
  search, as on Day 21.
- Matching codecs by their magic bytes paid off: Day 21's decoder already covered gzip, zlib, bz2, xz and zip, so a
  "new" wrapper cost nothing.
