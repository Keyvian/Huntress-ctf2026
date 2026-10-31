# 👶 A Little Based

| | |
|---|---|
| **Day** | 01 |
| **Lane** | 👶 Warmups |
| **Challenge ID** | `warmups-day-01` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/solve_based.py`](../solvers/solve_based.py) |

## Prompt
> Everyone has to start somewhere. I hear sixty-four is a good base.

## TL;DR
`blob.txt` is one line of Base64. Decoding it gives the sentence every warmup uses for the rest of the event:
`Nice work decoding this warmup! To solve, submit this exact answer to the Game Master: <slug>`. The answer is the
slug `word-word-word-NN`. Mastery wraps three such blobs in a ZIP, each with a `01<TAB>` index prefix.

## Artifact
- One question, answer id `message`: *"Decode the assigned blob completely. What exact answer slug does its final
  non-empty decoded line instruct you to submit?"* Format `pattern` (three lowercase words, hyphens, two-digit number),
  normalization `trim`.
- Single Solve: `blob.txt`, 148 bytes, one line of padded Base64 (`TmljZSB3b3JrIGRl…`).
- Time Trial: same shape with a fresh slug (144 bytes).
- Mastery: answer ids `set1.message`…`set3.message`. The default artifact is a stored ZIP containing `blob-01.txt`…
  `blob-03.txt`; each member is one line `01\t<base64>`. `delivery=1` and `2` return `{"error":"invalid_delivery"}`.

## Solution
1. Decode Base64, repeating while the result still looks like Base64 (the solver peels nested layers and stops on
   non-printable output or once a slug appears).
2. Take the final non-empty line and extract `[a-z]+-[a-z]+-[a-z]+-\d{2}`.
3. For Mastery, read every ZIP member, strip the leading `NN\t` index, then decode as above.

```python
INDEX_PREFIX = re.compile(r"^\s*\d+[\t ]+(.*)$")      # "01\t<base64>"
payload = strip_index(final_nonempty_line(text))
decoded, _ = decode_completely(payload.encode())      # base64 until it stops looking like base64
slug = SLUG.search(final_nonempty_line(decoded)).group(0)
```

## Time Trial & Mastery
Both timed modes had roughly 30-second deadlines. The solver does start, fetch, decode and submit in one process.
Mastery took three attempts. The first used per-question `delivery=i` fetches, got one ZIP plus two `invalid_delivery`
errors, and returned `invalid_answers`. The second unpacked the ZIP but choked on the `01\t` prefix. The third, after a
`retry`, stripped the prefix and came back CORRECT. Each retry regenerates the slugs, so the solver always decodes the
bytes fetched in the same attempt.

## Lessons / gotchas
- Mastery bundles all sets in the **default** artifact as a ZIP. Map members to questions by the `artifact` filename.
- Strip the `NN\t` row index before decoding. It is row 01 of the multi-row format that later mastery bundles grow
  one row per day (see the [lane overview](../lanes/warmups.md)).
- An expired timed attempt regenerates its material on `start`/`retry`. Never reuse decoded answers across attempts.
