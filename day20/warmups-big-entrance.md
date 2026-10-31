# 👶 Big Entrance

| | |
|---|---|
| **Day** | 20 |
| **Lane** | 👶 Warmups |
| **Challenge ID** | `warmups-day-20` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day20_quick/warm20.py`](../solvers/day20_quick/warm20.py) (+ debug aid [`rows20.py`](../solvers/day20_quick/rows20.py)) |

## Prompt
> Same bar. This time the big one goes first.

## TL;DR
Hex of **UTF-16BE** text with BOM (`feff 004e 0069 …`). Day 19's `u16()` already handled the `FE FF` branch, so Single
Solve and Time Trial needed no change. Mastery broke the solver: at 20 rows, the old combination search hung, and we
replaced it with a **template-guided, left-to-right search**.

## Artifact
- Single Solve and Time Trial: `blob.txt`, hex starting `feff`.
- Mastery: 98 sets, 20 rows each: `base64, rot13, hex, binary, decimal, octal, URL, HTML, JSON \u, base32, base64url,
  reverse, atbash, caesar+7, rot47, Morse→hex, Bacon→hex, rail fence 3, hex-UTF16LE, hex-UTF16BE`.

## Solution
Every row decoded on its own, but `warm19` sat at 99% CPU and 1.8 GB for 6+ minutes and was killed. Two problems:
`solve_mixed()` only looked at the first 4096 `itertools.product` combinations and never reached the right one, and
`eng_score()` returned a perfect `0.0` for strings with no letters (ROT47 or Caesar of digit rows). After that it fell
into an uncapped multi-layer search (≈7^10 strings). `warm20.py` fixes all three:

```python
T = "nice work decoding this warmup! to solve, submit this exact answer to the game master: "
def solve_template(cands):                       # cands = per-row candidate lists, in row order
    states = [("", "")]                          # (lowercased text so far, original-case text)
    for lc in cands:
        nxt = []; seen = set()
        for low, orig in states:
            for x in lc:
                nl = low + x.lower()
                ok = T.startswith(nl) if len(nl) <= len(T) else \
                     nl.startswith(T) and bool(SLUG_PART.match(nl[len(T):]))
                if ok and nl not in seen:
                    seen.add(nl); nxt.append((nl, orig + x))
        states = nxt[:5000]
        if not states: return None
    for low, orig in states:
        tail = low[len(T):] if len(low) > len(T) else ""
        if SLUG_FULL.match(tail): return tail.rstrip("."), orig      # ^[a-z]+-[a-z]+-[a-z]+-\d{2}\.?$
```
1. The concatenation must stay a prefix of the known sentence, then become a slug. Wrong candidates are pruned
   immediately.
2. `eng_score()` returns −9 for strings with no letters.
3. The whole-blob search is deduplicated, sorted by English score, and capped at 64 states per depth.

## Time Trial & Mastery
All modes were regular untimed attempts. Single Solve and Time Trial were CORRECT with the Day-19 solver. Offline,
`warm20.py local` decoded 98/98 slugs in ~5 s, and the Single and Time Trial blobs still passed. Mastery was submitted on
the same still-open attempt (`start` resumes it) and came back CORRECT (98/98, 4.7 s).

## Lessons / gotchas
- The plaintext is known except for the slug, so use it as a constraint, not just as a final check. Pruning by prefix
  turns an exponential search into a linear one.
- Scoring functions need a floor for degenerate input. "No letters" must score worst, not best.
- Cap every search frontier. An unbounded search does not fail, it just never finishes.
