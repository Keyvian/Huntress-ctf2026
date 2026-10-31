# 👶 Opposite Day

| | |
|---|---|
| **Day** | 13 |
| **Lane** | 👶 Warmups |
| **Challenge ID** | `warmups-day-13` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day13_quick/warm13.py`](../solvers/day13_quick/warm13.py) |

## Prompt
> A met Z. They really hit it off.

## TL;DR
Atbash (a↔z, b↔y, …, case kept; digits and punctuation untouched). Single Solve and Time Trial are trivial. Mastery had
a trap. The slug fragments in rows 11–13 are short letter strings, and Atbash, ROT13 and reversal **all** turn them into
plausible slugs. The fix: learn which codec each row position uses across the whole bundle, scored with an English
letter-trigram model.

## Artifact
- Single Solve and Time Trial: one Atbash line, e.g. `Mrxv dlip … Tznv Nzhgvi: <atbash slug>` → `Nice work … Game Master: …`.
- Mastery: 63 sets, 13 rows each. Learned row order: `01 b64 · 02 rot13 · 03 hex · 04 binary · 05 decimal · 06 octal ·
  07 url · 08 html · 09 json \u · 10 base32 · 11 base64url · 12 reverse · 13 atbash`.

## Solution
1. `atbash(s) = s.translate(str.maketrans(a–z A–Z, z–a Z–A))` was added to `layers()` and to the per-row decoder.
2. `line_decode_l()` now labels every candidate with its codec.
3. `learn_positions()` takes all blobs in the bundle and, for each `(row index, codec)` pair, averages an English
   letter-trigram score (`eng_score`, the model built from `/usr/share/common-licenses`). Each row position uses a
   fixed codec, so averaging across 63 blobs makes the right codec stand out even where one short fragment is ambiguous.
4. `solve_mixed()` sorts each row's candidates by the learned codec rank, then by English score, and searches the product
   for `Nice work … Game Master: <slug>`.

```python
for i, f in rows:
    for lab, x in line_decode_l(f):
        a = agg.setdefault(i, {}).setdefault(lab, [0.0, 0]); a[0] += eng_score(x); a[1] += 1
POS_RANK[i] = sorted(d, key=lambda lab: -(d[lab][0] / d[lab][1]))
```
Fixed examples: `-timmus-` (rev) → `-summit-`, `xlkkvi-23` (atbash) → `copper-23`.

## Time Trial & Mastery
New today: the Time Trial and Mastery warmups came back with `deadline: None` (untimed), so Mastery could be inspected
and resubmitted. The first Mastery submit was `incorrect`, with garbage such as `quiet-grnnfh-copper-23`, where the middle
word was ROT13 soup. The second submit, using the learned codec per position, was CORRECT for all 63.

## Lessons / gotchas
- Never accept the first combination that matches the template. Short fragments are ambiguous between the letter
  ciphers. Pool evidence across the bundle: same row index, same codec.
- Untimed modes let you resubmit after `incorrect`. Use them to debug.
