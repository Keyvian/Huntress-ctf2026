# 👶 Two of a Kind

| | |
|---|---|
| **Day** | 04 |
| **Lane** | 👶 Warmups |
| **Challenge ID** | `warmups-day-04` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/recon.py`](../solvers/recon.py) (per-row reconstructor) · [`solvers/solve_warmup.py`](../solvers/solve_warmup.py) (single/TT) · [`solvers/warmup_mastery3.py`](../solvers/warmup_mastery3.py) (a failed intermediate) |

## Prompt
> There are only two sides to this story.

## TL;DR
Base 2. Single Solve and Time Trial are 8-bit binary groups (`01001110 01101001 …` = `Ni…`). Mastery was the real
change. Each blob is a numbered list where **every row uses a different codec**: row 01 Base64, row 02 ROT13, row 03
hex, row 04 binary. Decode each row on its own terms and concatenate to rebuild the sentence.

## Artifact
- Single Solve: `blob.txt`, 998 bytes of space-separated 8-bit groups.
- Mastery: 18 sets. When inspected, the default artifact and each `delivery=K-1` returned the raw text of one blob, for
  example:
  ```
  01	TmljZSB3b3JrIGRlY29kaW5nIHRoaXMgd2Fy      -> "Nice work decoding this war"
  02	zhc! Gb fbyir, fhozvg guvf              -> "mup! To solve, submit this "
  03	657861637420616e73776572…                -> "exact answer…"
  04	<8-bit groups>                          -> "…e Master: <slug>"
  ```

## Solution
- Single/Time Trial: we added a binary transform to `solve_warmup.py`. If the text is only `[01\s]+` and the bit count
  is a multiple of 8, pack it into bytes.
- Mastery ([`recon.py`](../solvers/recon.py)): for each `NN\t<payload>` row, generate every candidate decoding
  (identity, ROT13, Base64, hex, Base32, binary). Score each candidate against words known from the template (`nice`,
  `work`, `decod`, `warmup`, `submit`, `game`, `master`, …), add a bonus for the slug regex and for printable characters,
  and keep the best. Concatenate, then take the slug after `Master:`.

```python
for l in lines:
    payload = re.match(r"^\s*\d+[ \t]+(.*)$", l).group(1)
    pieces.append(max(line_cands(payload), key=score))
full = "".join(pieces)
slug = re.search(r"[Mm]aster[:\s]+([a-z]+-[a-z]+-[a-z]+-\d{2})", full).group(1)
```

## Time Trial & Mastery
Time Trial (one binary blob) was CORRECT once binary support was added. Mastery cost one `incorrect` submit. The
whole-blob search from the final row returned slugs that were still ROT13'd (`rntre-fgnesvfu-ahttrg` = `eager-starfish-nugget`),
because the final row on its own only holds the end of the sentence. We next tried joining the rows as one Base64 string
([`warmup_mastery3.py`](../solvers/warmup_mastery3.py)), and that decoded nothing. Printing one blob row by row showed
the per-row codecs. A per-delivery driver around `recon.reconstruct()` (start, fetch the 18 deliveries, rebuild, one
submit) then decoded 18/18 and came back CORRECT.

## Lessons / gotchas
- "Two of a Kind" covers two things: binary for the single blob, and mixed codecs in Mastery. From this day on, the
  Mastery bundle is a numbered, mixed-codec, row-per-fragment blob that grows by one row per day.
- Never let a "slug-shaped" result through without the template text around it. ROT13 of a slug still looks like a slug.
- Rate limiting showed up while debugging. The Mastery driver retries `rate_limited` fetches with a short sleep.
