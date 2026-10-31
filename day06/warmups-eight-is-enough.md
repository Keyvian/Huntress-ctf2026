# 👶 Eight Is Enough

| | |
|---|---|
| **Day** | 06 |
| **Lane** | 👶 Warmups |
| **Challenge ID** | `warmups-day-06` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | Homebase-only `~/d6/w6.py`; not copied into this repo (Day 8's `w8.py` was derived from it). Same per-row approach as [`solvers/recon.py`](../solvers/recon.py). |

## Prompt
> Someone counted on eight fingers. Again.

## TL;DR
Octal. The single blob is space-separated 3-digit octal codes (`116 151 143 145 040 …` = `Nice `), decoded with
`chr(int(t, 8))`. Mastery adds an octal row (row 06) to the mixed-codec blob. The bug was an octal slug row that the
scorer **left undecoded**, because a line of digits scored as well as its decoding.

## Artifact
- Single Solve: `blob.txt`, one line of octal byte values. Spaces show up as `040`.
- Mastery: 28 sets, one delivery per set (`delivery=0..27`), each a 6-row `NN\t` blob (Base64, ROT13, hex, binary,
  decimal, octal).

## Solution
- Single: `"".join(chr(int(t, 8)) for t in re.findall(r"[0-7]+", txt))`, then the slug after `Master:`.
- Mastery `w6.py`: per-row candidates (identity, ROT13, Base64, hex, Base32, binary, plus octal and decimal for rows that
  are digits only), best by score, concatenate. The fix that made it reliable:

```python
def score(t):
    low = t.lower(); s = sum(10 for w in WORDS if w in low)
    if SLUG.search(low): s += 14
    if re.search(r"[a-z]+-[a-z]+-\d", low): s += 6
    L = max(len(t), 1)
    s += sum(c.isalpha() or c in "- " for c in t) / L * 4    # reward letters
    s -= sum(c.isdigit() for c in t) / L * 3               # penalize digit soup
    return s

def cands(p):
    out = [p] if re.search(r"[A-Za-z]", p) else []          # never keep a purely numeric row raw
```

## Time Trial & Mastery
Time Trial was CORRECT in 2.9 s. Mastery's first submit returned `invalid_answers`, because some blobs decoded to `None`.
The second run returned CORRECT. A later status check showed the mode as unsolved, so it was re-run. That run failed
on 6 of 28 blobs for two reasons. One fetch had hit `rate_limited` (the body was a JSON error, not a blob). In the
others, the octal slug row was kept as raw digits
(`…Game Master: bright-r141 151 156 …`). After the scoring fix above, fetches retried up to 10 times with a 0.6 s pause,
and the thread pool cut from 24 to 16 workers, Mastery returned CORRECT in 3.7 s.

## Lessons / gotchas
- When a row can stay as-is, the raw text competes with its own decoding. Drop the raw candidate for rows that are
  purely numeric.
- A `{"error":"rate_limited"}` body is not a blob. Check for it and retry the fetch before decoding.
- Confirm the mode is solved with a status/list check. A CORRECT on a re-run was the only way to clear the doubt here.
