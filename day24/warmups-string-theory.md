# 👶 String Theory

| | |
|---|---|
| **Day** | 24 |
| **Lane** | 👶 Warmups |
| **Challenge ID** | `warmups-day-24` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day24_quick/warm24.py`](../solvers/day24_quick/warm24.py) (= `warm23x.py` + [`ns_snippet.py`](../solvers/day24_quick/ns_snippet.py)); standalone decoder [`ns_warm.py`](../solvers/day24_quick/ns_warm.py) |

## Prompt
> Count carefully. The comma knows where to stop.

## TL;DR
**Netstrings** (`<length>:<data>,`, D. J. Bernstein's length-prefixed format). Every variant we saw used one netstring
per character: `1:N,1:i,1:c,1:e,…`. Concatenating the payloads gives the sentence. A netstring stream is unambiguous, so
the solver peels it **before** any other codec.

## Artifact
- Single Solve and Time Trial: `blob.txt`, a stream of `1:<char>,` items.
- Mastery: 118 sets (`blob-01.txt`…`blob-118.txt`, default ZIP), 24 mixed-codec rows; row 24 is a netstring fragment.

## Solution
```python
def ns_parse(b):                          # complete, exact stream or None
    out, i = [], 0
    while i < len(b):
        j = b.find(b":", i)
        if j <= i or j - i > 9 or not b[i:j].isdigit(): return None
        end = j + 1 + int(b[i:j])
        if b[end:end + 1] != b",": return None
        out.append(b[j + 1:end]); i = end + 1
        while i < len(b) and b[i:i + 1] in b" \n\r\t": i += 1   # whitespace between items tolerated
    return out
```
`ns_decode()` repeats the peel while the result is still a netstring stream (nested layers). In the solver:
- `solve_blob()` peels netstrings first, then hands the payload to the Day-23 solver, in case the payload is itself
  encoded.
- The `layers()` wrapper returns only the netstring decode when one parses, with no ROT/Base64 candidates.
- The row decoder adds an `ns` label (`nsgz`, `ns16` when the payload is compressed or UTF-16) and ranks it first.

## Time Trial & Mastery
All modes were regular untimed attempts. Single, Time Trial (256 unique attempts) and Mastery (118/118, 2.4 s compute)
were all CORRECT. Mastery grew from 113 to 118 sets.

## Lessons / gotchas
- Parse strictly: the full stream, exact lengths, a comma terminator after every item. A loose "digits and a colon" check
  would match timestamps or ratios in other rows.
- `warm24.py` is the last solver built by concatenating source. From here on, solvers have a `__main__` guard, and later
  days extend it by `import warm24` plus monkeypatching (see [Day 25](../day25/warmups-you-have-a-point.md)).
