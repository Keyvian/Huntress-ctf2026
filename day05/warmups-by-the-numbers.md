# 👶 By the Numbers

| | |
|---|---|
| **Day** | 05 |
| **Lane** | 👶 Warmups |
| **Challenge ID** | `warmups-day-05` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | Homebase-only scripts (`/tmp/w5solve.py`, `w5timed.py`, `w5mastery.py`); not copied into this repo. The per-row logic matches [`solvers/recon.py`](../solvers/recon.py) plus a numeric codec. |

## Prompt
> These characters have been reduced to numbers.

## TL;DR
Decimal ASCII codes: `78 105 99 101 32 …` = `Nice `. Single Solve is one line of space-separated decimals. Mastery
adds a decimal row (row 05) to the Day-4 mixed-codec blob. The tricky part was the clock. The 23-set Mastery had a
**~7-second** timer, so the 23 deliveries had to be fetched in parallel.

## Artifact
- Single Solve: `blob.txt`, 395 bytes, one line of decimal byte values.
- Mastery: 23 questions (`set1.message`…`set23.message` → `blob-01.txt`…`blob-23.txt`). The default artifact was **not**
  a ZIP: each set was its own delivery (`delivery=0..22`), a raw text blob of `NN\t` rows:
  `01 Base64 · 02 ROT13 · 03 hex · 04 binary · 05 decimal`.

## Solution
- Number rows: pull the integer tokens and try each base (10, 16, 8, 2 when the tokens allow it, plus `int(t, 0)` for
  prefixed forms). `chr()` each value and keep the candidate that scores best against the template words.
- Mastery: the Day-4 per-row reconstructor (best candidate per row by template-word score, concatenate, regex the slug
  after `Master:`) with the decimal codec added.

```python
toks = re.findall(r"[0-9A-Fa-fxXoObB]+", line)
for base in (10, 16, 8, 2, 0):
    cands.append("".join(chr(int(t, base)) for t in toks))   # guarded per base
best = max(cands, key=score)                                  # template words + slug + printable
```

## Time Trial & Mastery
- Time Trial: CORRECT on the first run.
- Mastery: the first submit was `incorrect`, most likely because the set-to-blob mapping reused one blob. Inspection
  showed one delivery per set. A dry run measured the deadline: started 13:25:05.99, deadline 13:25:12.99, so 7 s. Fetching 23
  deliveries one after another could not fit. The final script starts the attempt, fetches all 23 deliveries from a
  thread pool, decodes and submits once. Fetch plus decode took 5.2 s, the whole run 5.8 s, and the result was CORRECT.

## Lessons / gotchas
- Delivery layout changes from day to day: a ZIP on Days 1–3, one delivery per set on Days 4–6, back to one ZIP on Day 8.
  Check the default artifact before deciding how to fetch.
- Under a timer of a few seconds, latency is the cost, not decoding. Parallelize fetches and submit exactly once.
- Numeric rows are ambiguous between bases. Score candidates by English and template words rather than trusting one base.
