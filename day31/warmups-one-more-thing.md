# 👶 One More Thing

| | |
|---|---|
| **Day** | 31 |
| **Lane** | 👶 Warmups |
| **Challenge ID** | `warmups-day-31` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day31_quick/warm31.py`](../solvers/day31_quick/warm31.py) (imports `warm30`) · check [`warm_check31.py`](../solvers/day31_quick/warm_check31.py) · peek [`peekwarm31.py`](../solvers/day31_quick/peekwarm31.py) |

## Prompt
> Thirty-two, a little pressure, then sixty-four. Unpack that thought.

## TL;DR
A three-layer finale. The text was encoded **Base32 → gzip → Base64**, so decoding runs in reverse: **Base64 → gunzip →
Base32**. The blob starts `H4sIAAAA…` (Base64 of the gzip magic, as on Day 21). The layer search from `warm30` solved
Single and Time Trial. Mastery's row 31 needed a strict decoder.

## Artifact
- Single Solve and Time Trial: one Base64 line starting `H4sI`.
- Mastery: 153 sets, **31 rows**, with row 31 the new three-step codec on one fragment.

## Solution
```python
def gz32(t):
    h = re.sub(r"\s+", "", re.sub(r"^\d+\t", "", t.strip()))
    if not h.startswith("H4sI"): return None
    s = base64.b32decode(gzip.decompress(base64.b64decode(h, validate=True))).decode("utf-8")   # failures -> None
    return s if s and all(c.isprintable() or c in "\r\n\t" for c in s) else None

warm26.STRONG_LABELS.add("gz32")
```
When `gz32` matches, `warm31.py` returns it alone, as a layer and as a row label. Without it, `warm30` did not finish
within 2 minutes on the Mastery bundle: the row fell through to the generic search.

## Time Trial & Mastery
All modes were regular untimed attempts. Single and Time Trial were CORRECT with the existing layer search. Mastery
computed in ~8 s with `warm31.py`. `warm_check31.py` re-ran every blob and checked: 153/153 exact template, row labels
`01..31`, the strict decodes of rows 29 (ROT13→Base64), 30 (double percent) and 31 (Base64→gunzip→Base32) joined into
each slug's tail, no duplicate slugs, every word that appears only once a real word. One submit, CORRECT, 153/153.

```python
r31 = base64.b32decode(gzip.decompress(base64.b64decode(rows[-1].split("\t", 1)[1]))).decode()
r30 = urllib.parse.unquote(urllib.parse.unquote(rows[-2].split("\t", 1)[1]))
r29 = base64.b64decode(codecs.decode(rows[-3].split("\t", 1)[1], "rot13")).decode()
assert msg.endswith(r29 + r30 + r31)
```

## Lessons / gotchas
- For a "then" chain, the prompt gives the **encoding** order. Decode in the opposite order.
- A strict decoder for the newest row is both the speed fix and the safety check. Verifying that the last rows' strict
  decodes join into the slug tail turns a long search into a simple assertion.
- That closed the lane: 31 days × 3 modes, with Mastery grown to 153 sets of 31 mixed-codec rows.
