# 👶 Bacon Bits

| | |
|---|---|
| **Day** | 17 |
| **Lane** | 👶 Warmups |
| **Challenge ID** | `warmups-day-17` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day17_quick/warm17.py`](../solvers/day17_quick/warm17.py) |

## Prompt
> Sixteen guests. Five little a's and b's apiece.

## TL;DR
A Bacon cipher with a twist. The blob is space-separated groups of five `a`/`b` letters. Read with a=0 and b=1, each group
is a 5-bit number, but only **16** values occur ("sixteen guests"). So each group is a **hex nibble**, and pairs of groups
form the bytes of the ASCII sentence. Example: `N` = 0x4E → `aabaa abbba` (00100, 01110).

## Artifact
- Single Solve and Time Trial: `blob.txt`, groups like `aabaa abbba aabba abaab …`.
- Mastery: 83 sets (`blob-01.txt`…`blob-83.txt` in one ZIP), mixed-codec `NN\t` rows, with row 17 a Bacon→hex fragment.

## Solution
`warm17.py` = `warm16.py` + `is_bacon()` / `bacon_decodes()`, wired into `layers()` and `line_decode_l()`:

```python
def bacon_vals(s):
    letters = re.sub(r"\s+", "", s.strip()).lower()
    return [int(letters[i:i+5].replace("a", "0").replace("b", "1"), 2) for i in range(0, len(letters), 5)]

v = bacon_vals(s)
if all(x < 16 for x in v):                       # 16-symbol alphabet -> nibbles
    out.append(("baconhex", binascii.unhexlify("".join("%x" % x for x in v)).decode()))
# fallbacks: classic 26-letter and 24-letter (i/j, u/v merged) Bacon alphabets
```
`is_bacon()` only accepts text that is purely `a`/`b` and whitespace, with a letter count that is a multiple of 5 and
every token 5 long. That strictness keeps it from firing on ordinary rows.

## Time Trial & Mastery
Both were plain `start` attempts, regular and untimed (`deadline: None`), as on Day 16. Time Trial was CORRECT
(256 unique attempts available). Mastery was CORRECT for all 83 sets, with 1.9 s of compute.

## Lessons / gotchas
- Read the numbers in the prompt literally. "Sixteen" ruled out the textbook 24- and 26-letter Bacon alphabets before
  any decoding. The solver still keeps them as fallbacks.
- Strict syntax checks (alphabet, group length, count modulo 5) are what keep each new codec from creating false
  candidates on the 16 older row types.
