# 📱 Name Collapse

| | |
|---|---|
| **Day** | 17 |
| **Lane** | 📱 Mobile Android |
| **Challenge ID** | `mobile-android-day-17-name-collapse` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day17_quick/mob17.py`](../solvers/day17_quick/mob17.py) |

## Prompt
> Restore behavior after deterministic identifier shrinking and decoy insertion.

## TL;DR
New codec **`indexed`**: `{"codec":"indexed","data":"<20 scrambled chars>","order":[20 ints]}`. The grader's rule
is a **scatter**, `out[order[i]] = data[i]`, which rebuilds `ANS-<16 HEX>`. jadx on the 2.6 KB dex showed an
R8-renamed class `a` that only holds constants (`CODEC="indexed"`, `CONTROL="identifier_obfuscation"`), so the whole
decode lives in the JSON.

## Artifact
- `assets/huntress_puzzle.json` with `data` (20 characters, a permutation of the answer) and `order` (20 indices).
- `classes.dex` (2.6 KB): class `a` (constants only) and the usual `ChallengeActivity` WebView stub pointing at
  `127.0.0.1:19090`.
- Mastery: 5 sets, with codecs `xor`, `reverse`, `hex`, `caesar`, `indexed`.

## Solution
**Theme.** R8/ProGuard "identifier shrinking" renames classes, methods and fields to `a`, `b`, `c`… using a
deterministic mapping, and obfuscators add decoy members. Restoring behavior means reading code by structure
(call graph, constants, string use) instead of by name. In this APK the renamed class carries nothing but the codec
label.

**Extraction:**

```python
def indexed_dec(data, order):
    n = max(order) + 1
    out = [None] * n
    for i, o in enumerate(order):
        if i < len(data):
            out[o] = data[i]                                  # scatter (graded)
    cands = ["".join(c for c in out if c is not None),
             "".join(data[o] for o in order if o < len(data))]  # gather (fallback)
    return next((s for s in cands if ANS.fullmatch(s)), cands[0])
```

If `data` is longer than `order`, both rules drop the extra (decoy) characters. Scatter and gather are inverse
permutations, so for an arbitrary `order` only one of them can produce `ANS-` followed by 16 uppercase hex digits.

## Time Trial & Mastery
- Time Trial and Mastery were regular untimed attempts (plain `start`, `deadline: None`), as on Day 16.
- `mob17.py` gained `--save <dir>` (stores `start.json` + `artifact.bin` per attempt) and `--retry`/`--practice`
  switches. The saved artifacts later made local dry runs easy.

## Lessons / gotchas
- Day 5 (`split`) and Day 17 (`indexed`) are both permutations, at chunk and character granularity respectively.
  In both cases the scatter reading was the graded one.
- jadx was used only to confirm that no decoder lives in the code. Nothing in the APK was executed.
