# 👶 Back at You

| | |
|---|---|
| **Day** | 12 |
| **Lane** | 👶 Warmups |
| **Challenge ID** | `warmups-day-12` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day12_quick/warm12.py`](../solvers/day12_quick/warm12.py) |

## Prompt
> Maybe we started at the wrong end.

## TL;DR
The plaintext is simply reversed. The blob starts with the reversed slug, `NN-…-… :retsaM emaG eht ot …`, and `s[::-1]`
restores it. `warm12.py` adds reversal candidates (the whole text, and each line separately) to `layers()` and to the
per-row decoder. The breadth-first search finds the `Game Master: <slug>` line.

## Artifact
- Single Solve and Time Trial: `blob.txt`, the sentence written backwards.
- Mastery: 58 sets (`blob-NN.txt` in one ZIP). From Day 13's learned row order, row 12 was a reversed fragment.

## Solution
```python
out.append(t[::-1])                                          # whole text reversed
out.append("\n".join(l[::-1] for l in t.splitlines()))       # each line reversed
# and in the per-row decoder:
add("rev", f[::-1])
```
Everything else is unchanged from [Day 11](../day11/warmups-safe-travels.md).

## Time Trial & Mastery
Time Trial: CORRECT in 1.2 s. Mastery: CORRECT on the first submit, after 24.7 s of wall time. The day's note calls
the run "untimed-safe" but does not record a deadline.

## Lessons / gotchas
- Reversal is the first codec that turns real text into **letter soup** rather than a different alphabet. A reversed
  short fragment can look like plausible English. This caused trouble the very next day ([Day 13](../day13/warmups-opposite-day.md)).
- Reverse each line as well as the whole text. A multi-line blob reversed line by line is not the same as one reversed
  as a whole.
