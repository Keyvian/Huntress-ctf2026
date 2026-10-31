# 👶 Off the Rails

| | |
|---|---|
| **Day** | 18 |
| **Lane** | 👶 Warmups |
| **Challenge ID** | `warmups-day-18` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day18_quick/warm18.py`](../solvers/day18_quick/warm18.py) (+ standalone [`rail.py`](../solvers/day18_quick/rail.py)) |

## Prompt
> Three rails. One very zigzag commute.

## TL;DR
A rail-fence (zigzag) transposition with **3 rails**. The plaintext was written diagonally down and up across three rails,
then read off rail 0, rail 1, rail 2. To decode, compute which rail each position falls on, then refill the positions
rail by rail from the ciphertext. No characters change, only their order.

## Artifact
- Single Solve and Time Trial: `blob.txt`, the sentence scrambled by a 3-rail fence.
- Mastery: 88 sets (`blob-01.txt`…`blob-88.txt`, one ZIP), mixed-codec `NN\t` rows; row 18 is a rail-fence fragment.

## Solution
```python
def rail_idx(n, rails):                 # rail number of each plaintext position (0,1,2,1,0,1,2,…)
    idx = []; r = 0; d = 1
    for _ in range(n):
        idx.append(r)
        if r == 0: d = 1
        elif r == rails - 1: d = -1
        r += d
    return idx

def rail_dec(c, rails):
    idx = rail_idx(len(c), rails); out = [None] * len(c); pos = 0
    for rr in range(rails):             # ciphertext = rail 0 chars, then rail 1, then rail 2
        for i in range(len(c)):
            if idx[i] == rr: out[i] = c[pos]; pos += 1
    return "".join(out)
```
`rail_candidates()` tries rails 3, 2, 4, 5, 6. A decode that starts with "nice work" or contains "game master" is returned
**alone**, so the search does not fan out. Rail decodes became whole-blob layers (after the Bacon and Morse checks) and
`rail2`/`rail3`/`rail4` row codecs. The per-position English ranking ([Day 13](../day13/warmups-opposite-day.md)) picked
the right one for row 18.

## Time Trial & Mastery
The warmup timed modes had **real timers** this day: Time Trial 30 s, Mastery 105 s for 88 sets. The metadata and mobile
lanes stayed untimed. The single-process solver needed ~1 s for Time Trial and 1.9 s for Mastery, and both were CORRECT
on the first submit.

## Lessons / gotchas
- A transposition keeps every letter, so English-letter statistics can't separate candidates. Only word order does.
  Matching the template text ("nice work", "game master") is the reliable test.
- Don't assume yesterday's timer policy holds. Days 16–17 were untimed, Day 18 had timers, and Day 19 was untimed again.
