# 👶 Half a Turn

| | |
|---|---|
| **Day** | 02 |
| **Lane** | 👶 Warmups |
| **Challenge ID** | `warmups-day-02` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/solve_warmup.py`](../solvers/solve_warmup.py) |

## Prompt
> Thirteen steps forward. Funny how that works out.

## TL;DR
ROT13. "Half a turn" of a 26-letter alphabet is 13, so applying ROT13 again inverts it:
`Avpr jbex qrpbqvat guvf jnezhc!` becomes `Nice work decoding this warmup!`. We replaced the Day-1 Base64-only script with
a general warmup solver that tries several transforms and stops at the first output naming the Game Master.

## Artifact
- Single Solve: `blob.txt`, 108 bytes of ROT13 text. The slug is rotated too.
- Time Trial: one fresh blob, same shape.
- Mastery: 8 sets (`set1.message`…`set8.message`) mapped to `blob-01.txt`…`blob-08.txt`.

## Solution
`solve_warmup.py` does a breadth-first search over one-layer transforms, up to three layers deep:

```python
def transforms(s):
    yield s
    yield codecs.decode(s, "rot_13")
    yield base64.b64decode(s + pad).decode("utf-8", "replace")   # and its ROT13
    yield base64.b32decode(s + pad).decode("utf-8", "replace")
    yield binascii.unhexlify(re.sub(r"\s", "", s)).decode("utf-8", "replace")
```

A candidate wins when it contains a slug **and** `Game Master` (or `submit`). The search starts from the final
non-empty line with any `NN\t` index removed, and also from the whole text. To collect files, the solver unpacks the
default artifact plus `delivery=0..9`, recursing into nested ZIPs, and matches each question to a file by the basename in
its `artifact` field (falling back to set order).

## Time Trial & Mastery
Both were run back to back right after Single Solve, with the same solver. Time Trial was CORRECT on the first try,
and all 8 Mastery slugs were correct in one submit. The timers were short and server-enforced, but a one-layer decode takes milliseconds.

## Lessons / gotchas
- Don't just pick an output that looks like a slug. Check it against the template text ("Game Master"), because ROT13
  also turns a slug into something slug-shaped. This bit us on Day 4.
- Probing `delivery=0..9` cost little here. On later, heavier timed modes that many requests could outlast the
  deadline, so later solvers fetch the default artifact first.
