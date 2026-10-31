# 👶 Back in Sixteen

| | |
|---|---|
| **Day** | 28 |
| **Lane** | 👶 Warmups |
| **Challenge ID** | `warmups-day-28` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day28_quick/warm28.py`](../solvers/day28_quick/warm28.py) (imports `warm26`) · [`warm_audit26.py`](../solvers/day28_quick/warm_audit26.py) |

## Prompt
> Our sixteen-fingered friend is walking backwards.

## TL;DR
Hex (the Day-3 sixteen-fingered friend) written **backwards, character by character**. Reverse the string, then
unhexlify: `bytes.fromhex(s[::-1])`. Reversing per character also swaps the two nibbles of every byte, so this is not
the same as reversing the byte order. The search over existing whole-blob layers (reverse, then hex) already solved
Single and Time Trial. Mastery's new row needed a dedicated decoder.

## Artifact
- Single Solve and Time Trial: one reversed hex string.
- Mastery: 138 sets, **28 rows**. The Day-27 codecs plus **row 28, reversed hex**, e.g. `4373d286` → reverse →
  `682d3734` → `h-74`.

## Solution
```python
def revhex(t):
    h = re.sub(r"\s+", "", t)
    if len(h) < 2 or len(h) % 2 or not re.fullmatch(r"[0-9A-Fa-f]+", h): return None
    s = bytes.fromhex(h[::-1]).decode("utf-8")
    return s if s and all(c.isprintable() or c in "\r\n\t" for c in s) else None

warm26.STRONG_LABELS.add("revhex")          # a strict row codec: outranks the letter-cipher candidates
```
`warm28.py` imports `warm26` (which chains `warm24` ← `warm25` ← `warm26`), adds `revhex` to the front of `layers()`, adds
a `revhex` row label, and monkeypatches both into `warm24`.

## Time Trial & Mastery
All modes were regular untimed attempts. Single and Time Trial (256 unique attempts) were CORRECT. The first Mastery
dry run with `warm26` got stuck: row 28 matched no row decoder, so `solve_mixed` fell into the very slow whole-blob
fallback (99% CPU for minutes) and was killed. With `warm28.py`, all 138 blobs decoded in 4 s. Checks before the one
submit: `warm_audit26.py` (0 inexact lines, all slug words real, its "odd structure" flag only noting 28 rows instead of
27), an independent check that every slug ends with the row-28 `revhex` decode (0 mismatches), and offline slugs equal
to the dry run's. CORRECT, 138/138.

## Lessons / gotchas
- An undecodable row doesn't fail fast. It drops into a fallback that takes minutes. Run `warm<N>.py local` on **one**
  extracted blob (~1 s) before the full Mastery dry run, and add the new codec first.
- Cross-check the slug against the new row's own strict decode. The slug tail must equal what row N decodes to.
