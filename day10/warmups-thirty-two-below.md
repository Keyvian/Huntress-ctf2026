# 👶 Thirty-Two Below

| | |
|---|---|
| **Day** | 10 |
| **Lane** | 👶 Warmups |
| **Challenge ID** | `warmups-day-10` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day10_quick/warm10.py`](../solvers/day10_quick/warm10.py) |

## Prompt
> Same neighborhood. Smaller alphabet.

## TL;DR
Base32: same neighborhood as Base64, smaller alphabet (`A–Z2–7`). The single blob is one Base32 string. Mastery is
10 indexed rows, each fragment in a different codec, with Base32 as the new row 10. This was the first day of the
three-agent parallel automation. `warm10.py` became the base of every later warmup solver.

## Artifact
- Single Solve and Time Trial: `blob.txt`, one Base32 string.
- Mastery: 48 sets, one ZIP of `blob-NN.txt`. Each blob has 10 rows `NN\t<fragment>`, concatenated in index order:
  `01 base64 · 02 rot13 · 03 hex · 04 binary (8-bit groups) · 05 decimal · 06 octal (e.g. 040) · 07 URL %xx ·
  08 HTML &#NN; · 09 JSON "\uXXXX" · 10 Base32`.

## Solution
`warm10.py` has two paths:
- **Whole blob** (`layers()`): a breadth-first search, up to 8 layers deep, over Base32 (re-padded), Base64, hex and
  ROT13. It stops when the final line contains `Game Master` and a slug.
- **Mixed rows** (`line_decode()`): each fragment is detected by **syntax** before decoding, and only printable-ASCII
  results are kept. A decimal-or-octal row is decided by the tokens: a leading-zero token means octal, any `8`/`9` means
  decimal, otherwise both are tried. `solve_mixed()` then searches the product of per-row candidates (capped at 4096
  combinations) for a message that starts with `Nice work` and ends in `Game Master: <slug>`.

```python
lead0 = any(len(t) > 1 and t[0] == "0" for t in toks)
order = [octv, dec] if lead0 else [dec, octv]
...
TEMPLATE = re.compile(r"Game Master: ([a-z]+-[a-z]+-[a-z]+-\d{2})$")
```

## Time Trial & Mastery
Time Trial was CORRECT. Mastery had about a 12 s timer. The first run used the old single-codec decoder, got no
answers, and still **submitted an empty answer set** → `incorrect`. The solver now aborts when the number of answers is
below the number of `answer_ids`. A plain `start` then resumed the expired attempt (`result: expired`), so we called
`op=retry` for a fresh ranked attempt. 48/48 decoded and the submit came back CORRECT.

## Lessons / gotchas
- Never submit a partial or empty answer map in an all-or-nothing mode. Make the solver refuse to.
- `start` on an expired attempt does not always hand out a new one. Use `retry` to roll fresh material.
- Day N's Mastery has N rows, and row k uses Day k's codec. Knowing this made every later day easy to predict.
