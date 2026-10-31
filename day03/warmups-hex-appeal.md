# 👶 Hex Appeal

| | |
|---|---|
| **Day** | 03 |
| **Lane** | 👶 Warmups |
| **Challenge ID** | `warmups-day-03` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/solve_warmup.py`](../solvers/solve_warmup.py) |

## Prompt
> Sixteen seems like a perfectly reasonable number of fingers.

## TL;DR
Base 16. The blob is the ASCII sentence written as hex (`4e696365…` = `Nice…`). The Day-2 general solver already had a
hex transform (`binascii.unhexlify` after removing whitespace), so it solved all three modes without changes.

## Artifact
- Single Solve and Time Trial: `blob.txt`, one hex string. The decoded final line names the slug.
- Mastery: 13 sets, `blob-01.txt`…`blob-13.txt`, answer ids `setN.message`.

## Solution
Same pipeline as [Day 2](../day02/warmups-half-a-turn.md). Take the final non-empty line, drop any `NN\t` index, then run
a breadth-first search over identity, ROT13, Base64, Base32 and hex. Keep the first output that contains both a slug and
`Game Master`.

```python
yield binascii.unhexlify(re.sub(r"\s", "", s)).decode("utf-8", "replace")
```

## Time Trial & Mastery
We ran all three modes back to back with one solver. Time Trial was CORRECT, and all 13 Mastery slugs were correct in a
single submit. The timer did not matter, since a hex decode is instant.

## Lessons / gotchas
- The prompt's number hint is the whole puzzle. Base 64 (Day 1), 13 (Day 2) and 16 (Day 3) each name the codec, and so
  do the "eight", "two" and "thirty-two" hints that come later.
- Keep every codec in one general solver instead of writing one per day. Mastery soon needed all of them at once.
