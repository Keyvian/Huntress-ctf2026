# 👶 Under Pressure

| | |
|---|---|
| **Day** | 21 |
| **Lane** | 👶 Warmups |
| **Challenge ID** | `warmups-day-21` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day21_quick/warm21.py`](../solvers/day21_quick/warm21.py) |

## Prompt
> A familiar wrapper. Something compressed inside.

## TL;DR
Base64 (the familiar wrapper) of a **gzip** member (something compressed). The blob starts `H4sI…`, which is Base64 for
the gzip magic `1F 8B 08`. Base64-decode, then `gzip.decompress`. `warm20` had no decompression step and returned
nothing, so `warm21.py` adds `inflate()` to every decode path.

## Artifact
- Single Solve and Time Trial: `blob.txt`, one Base64 line starting `H4sI`.
- Mastery: 103 sets, 21 rows each. The Day-20 mix plus **row 21 = Base64-gzip** carrying the slug tail.

## Solution
`inflate()` decompresses by magic bytes only:

```python
def inflate(b):
    if b[:2] == b"\x1f\x8b": return gzip.decompress(b)
    if b[:1] == b"\x78" and b[1:2] in (b"\x01", b"\x5e", b"\x9c", b"\xda"): return zlib.decompress(b)
    if b[:3] == b"BZh": return bz2.decompress(b)
    if b[:6] == b"\xfd7zXZ\x00": return lzma.decompress(b)
    if b[:4] == b"PK\x03\x04": ...   # single-member zip -> its content
    return None                    # raw deflate is deliberately NOT guessed
```
It is applied in three places: (a) to the raw blob in `solve_blob()`, (b) to every byte candidate in `layers()` (up to 4
nested layers), and (c) to every byte candidate in the row decoder (label suffix `gz`, e.g. `b64gz`).

## Time Trial & Mastery
All modes were regular untimed attempts. Before the fix, the mixed-row path decoded 0/103 and fell into the slow
fallbacks (145 s). After it, `solve_template()` decoded 103/103 in 1.7 s, and Mastery came back CORRECT, submitted on
the same still-open attempt. The morning's headless quick agent had died partway through the lane: Single Solve was
banked, but its log file was 0 bytes. The rest was resumed by hand from the saved attempts and the `op=list` solved flags.

## Lessons / gotchas
- When a new layer appears ("wrapper" themes), add it to **all three** decode paths: raw blob, multi-layer search, and
  per-row fragments. In Mastery the new codec is just one more row.
- Never add header-less (raw deflate) guesses to a layer search. Arbitrary bytes sometimes "inflate", which would replace
  valid decodings with garbage.
- An empty agent log plus partial banking means the agent crashed, not that the lane is finished.
