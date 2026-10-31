# 📱 Predictable Crypto

| | |
|---|---|
| **Day** | 14 |
| **Lane** | 📱 Mobile Android |
| **Challenge ID** | `mobile-android-day-14-predictable-crypto` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day14_quick/mob14.py`](../solvers/day14_quick/mob14.py) |

## Prompt
> Exploit seeded nonces or weak derivation without bypassing earlier storage gates.

## TL;DR
New codec **`caesar`**, e.g. `{"codec":"caesar","data":"JW\\6L><BL=…","key":9}`. Every character is shifted
by `key` on the **printable-ASCII ring 32..126** (95 symbols), not just letters. Shift back by 9 and `J`→`A`,
`\`→`S`, `6`→`-` gives `ANS-<16 HEX>`.

## Artifact
- Same APK shape as Days 9–13. Mastery: 3 sets, one APK per set.

## Solution
**Theme.** Predictable crypto means `java.util.Random` (or `SecureRandom.setSeed()` with a fixed seed) used for IVs
or nonces, AES-GCM nonce reuse, or keys derived with a single unsalted hash of a constant or device ID. All of
these let an attacker recompute the key or keystream. "Without bypassing earlier storage gates" points back to
Days 11–13.

**Extraction.** The new branch in `mob14.py` tries three readings and keeps the one that matches the answer
pattern:

```python
def caesar_dec(data, key):
    k = key if isinstance(key, int) else int(_key_bytes(key)[0])
    cands = [
        "".join(chr((ord(ch) - 32 - k) % 95 + 32) for ch in data),   # printable ring (the graded one)
        "".join(chr((ord(ch) - k) % 256) for ch in data),            # byte ring
    ]
    sk = k % 26                                                       # letters-only Caesar
    cands.append(data.translate(str.maketrans(az + AZ, az[-sk:] + az[:-sk] + AZ[-sk:] + AZ[:-sk])))
    return next((s for s in cands if ANS.fullmatch(s.strip())), cands[0])
```

A letters-only Caesar can't produce `ANS-` from `JW\6`, because the digits and `-` must move too. Only the
95-symbol ring works.

## Time Trial & Mastery
- Every timed mode that day (in all quick lanes) had a **30 s** deadline (`ranked_deadline_ms: 30000`, `uar` 0).
  Each solver ran start → download → decode → submit in one process and finished in 1–2 s.
- The same theme appeared in two lanes that day: the warmup used Caesar-7, and mobile used `caesar` with key 9 on
  the full printable range.

## Lessons / gotchas
- When the codec name is generic ("caesar"), generate every plausible alphabet or ring and let the strict
  `ANS-[0-9A-F]{16}` check pick one. Don't guess a single convention.
