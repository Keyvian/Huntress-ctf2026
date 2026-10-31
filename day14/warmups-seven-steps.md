# 👶 Seven Steps

| | |
|---|---|
| **Day** | 14 |
| **Lane** | 👶 Warmups |
| **Challenge ID** | `warmups-day-14` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day14_quick/warm14.py`](../solvers/day14_quick/warm14.py) |

## Prompt
> Caesar took a week off.

## TL;DR
A Caesar shift of **7** ("a week"). Each letter was shifted +7, so decoding shifts by −7: `Upjl dvyr … Nhtl Thzaly: …` →
`Nice work … Game Master: …`. `warm14.py` = `warm13.py` + `caesar(s, k)`, wired in both directions.

## Artifact
- Single Solve and Time Trial: one Caesar-7 line. Only letters shift, and the slug's digits stay as they are.
- Mastery: 68 sets of mixed-codec `blob-NN.txt` (14 rows; row 14 = Caesar).

## Solution
```python
def caesar(s, k):
    k %= 26
    t = str.maketrans(_AZ + _AZ.upper(), _AZ[k:] + _AZ[:k] + _AZ.upper()[k:] + _AZ.upper()[:k])
    return s.translate(t)

out.append(caesar(t, -7)); out.append(caesar(t, 7))      # whole-blob layers
add("c7", caesar(f, -7)); add("c7r", caesar(f, 7))       # per-row labels
```
The per-position codec learning from [Day 13](../day13/warmups-opposite-day.md) handled the new row with no tuning.

## Time Trial & Mastery
Every timed mode that day, warmups included, had a real **30 s** deadline (`ranked_deadline_ms: 30000`, no ranked
attempts left). The day before they had been untimed. Each solver ran start, download, compute and submit in one
process, which took 1–2 s, and all three modes were CORRECT. Mastery passed on the first submit.

## Lessons / gotchas
- The day's theme codec showed up in two lanes: warmup Caesar-7 here, and the mobile lane's `caesar` codec (key 9, which
  shifts the full printable-ASCII range rather than just letters).
- Whether a mode is timed changes from day to day. Keep the single-process start→fetch→submit pattern even when
  yesterday's modes were untimed.
