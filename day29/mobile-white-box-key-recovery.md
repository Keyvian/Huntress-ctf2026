# 📱 White Box Key Recovery

| | |
|---|---|
| **Day** | 29 |
| **Lane** | 📱 Mobile Android |
| **Challenge ID** | `mobile-android-day-29-white-box-key-recovery` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day29_quick/mob29.py`](../solvers/day29_quick/mob29.py) (+ [`dalvik.py`](../solvers/day29_quick/dalvik.py)) · cross-check [`check_tt29.py`](../solvers/day29_quick/check_tt29.py) · mapping check [`mobmap29.py`](../solvers/day29_quick/mobmap29.py) |

## Prompt
> Recover an equivalent key operation from challenge-owned table transformations, not a third-party protected binary.

## TL;DR
Single Solve introduced a v1 codec, **`table`** (`{"codec":"table","data":"6a7a825f…","key":41}`), and **the dex
ships no encoder**. The operation had to be recovered from the data itself. A search over 768 candidates showed
that only `plain[i] = (data[i] - key - 3*i) mod 256` gives a valid `ANS-` string. The Time Trial v2 build walks an
S-box built by an LCG. Its hand port first disagreed with the interpreter because **jadx renders a `shl-long` as
`1 << n`**, which reads like an int shift. The smali settled it, and the interpreter was right.

## Artifact
- Single Solve `white_box_key_recovery.apk`: puzzle as above. The dex only declares `CODEC="table"`,
  `CONTROL="white_box_table"` and the unreachable WebView URL.
- Time Trial: v2 `analysis`.
- Mastery: **13 sets** (default artifact = set 1, deliveries for sets 2–13), all v2, themes d01, d03, d07, d09, d10,
  d13, d15, d18, d19, d23, d24, d26, d29.

## Solution
**Theme.** White-box cryptography merges the key into lookup tables (T-boxes, encoded S-boxes) so it never appears
in memory. "Recover an equivalent key operation" is the standard attack: you don't need the key itself, only a
function that behaves the same, recovered from the tables.

**Single Solve: inferring the table operation.** With no encoder to read, `mob29.py` searches families of
per-index keyed operations and accepts only a unique match with `ANS-[0-9A-F]{16}`:

```python
for step in [3] + [s for s in range(256) if s != 3]:            # observed step first
    for op, f in (("sub", lambda c, i: (c - key - step * i) & 0xFF),
                  ("add", lambda c, i: (c + key + step * i) & 0xFF),
                  ("xor", lambda c, i: c ^ ((key + step * i) & 0xFF))):
        s = bytes(f(c, i) for i, c in enumerate(raw)).decode("latin1")
        if ANS.fullmatch(s): hits.append((step, op, s))
# 256 steps x 3 ops = 768 candidates -> exactly one hit: step 3 / sub
```

So the encoder was `data[i] = (plain[i] + key + 3*i) mod 256`. If a puzzle ever ships an explicit 256-entry
`table`/`sbox`, it is inverted first. The solver prints every other matching candidate, so an ambiguity would be
visible.

**Time Trial: the jadx shift trap.** The chain was `Util.mixTable…` → `Util.walkSbox…` (8 rounds: index
`j & 15` into a 16-entry table from `Tab.build`, an LCG with `x*6364136223846793005 + 1442695040888963407` and
`(x >>> 29) ^ x`, then `WhiteBoxKeyRecovery.tableTransform(i, x) = ((i*257) ^ x) & 255` placed at byte `(i & 7) * 8`)
→ `Util.mixRound…` → `Mix.f1` → `Util.finBox…` ^ const. jadx printed the byte placement with the factor

```java
1 << ((i & 7) * 8)
```

In Java an `int` shift masks the count to 5 bits, so `1 << 32` would be `1` again. The first hand port applied int
semantics and disagreed with `dalvik.py`. The smali (`apktool d` / `baksmali`) showed `const-wide 1` followed by
`shl-long`: a **long** shift. `check_tt29.py` prints both readings, and the long-shift reading matches the
interpreter. Submitted: `CORRECT`.

## Time Trial & Mastery
- All timed modes were regular untimed attempts. Time Trial `uar` 32.
- Mastery: `mobmap29.py` matched each question's package (`…package com.huntress.mobile.dNN.v…:`) against the DEX
  package of `artifact.bin` / `artifact<k>.bin`, 13/13. Computed in 5 s and submitted once: `CORRECT`.

## Lessons / gotchas
- v1 codecs can ship without an encoder. Infer the transform from the bytes, accept only a unique `ANS-` match, and
  keep the search in the solver so any ambiguity gets printed.
- When a hand port disagrees with the interpreter, read the smali before trusting jadx. Decompiled Java can hide
  the operand width.
