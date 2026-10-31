# 📱 Layered Protections

| | |
|---|---|
| **Day** | 30 |
| **Lane** | 📱 Mobile Android |
| **Challenge ID** | `mobile-android-day-30-layered-protections` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day30_quick/mob30.py`](../solvers/day30_quick/mob30.py) (+ [`dalvik.py`](../solvers/day30_quick/dalvik.py)) · search tool [`layer30.py`](../solvers/day30_quick/layer30.py) · cross-check [`check_tt30.py`](../solvers/day30_quick/check_tt30.py) |

## Prompt
> Unwind obfuscation, native indirection, runtime decryption, and integrity checks while proving the same backend effect.

## TL;DR
Single Solve introduced a v1 codec, **`layered`** (`{"codec":"layered","data":"TU49OyInJlUl…","key":12}`). Again
there was no encoder in the dex. A search recovered the composition: Base64-decode, XOR byte `i` with
`(key + i) & 255`, then **reverse**. The Time Trial v2 build "peels a stack" (a per-byte XOR, a byte reverse and a
gate function). Despite the prompt, there was no native library, no `Context` read and no integrity input in that
build. Mastery had 14 sets, all v2, and the interpreter handled them without changes.

## Artifact
- Single Solve `layered_protections.apk`: puzzle as above. The dex declares only `CODEC="layered"`,
  `CONTROL="layered_protections"` and the unreachable WebView URL.
- Time Trial: v2 `analysis`.
- Mastery: **14 sets** (default artifact = set 1, deliveries for sets 2–14), all v2, themes d02, d04, d05, d07, d09,
  d13, d15, d17, d19, d21, d23, d26, d29, d30.

## Solution
**Theme.** Commercial protectors stack several layers: identifier obfuscation, string encryption, JNI trampolines,
runtime-decrypted DEX, and tamper/signature checks. "Proving the same backend effect" means you can strip the layers
in any order as long as the final value is the same.

**Single Solve: searching the layer order.** `layer30.py` (and `mob30.decode_layered`) tries step 0..255 × {xor, add,
sub} × {reverse before, reverse after, both} on the Base64-decoded bytes and keeps candidates that fully match
`ANS-[0-9A-F]{16}`:

```python
b = base64.b64decode(p["data"]); k = p["key"]
for s in range(256):
    x = bytes(c ^ ((k + s * i) & 255) for i, c in enumerate(b))
    for label, v in (("xor_i", x), ("xor_i>rev", x[::-1]), ...):   # + sub/add and reverse-first variants
        if ANS.fullmatch(v.decode("latin1")):
            hits.append((s, label, v))
# exactly one hit: step 1, xor, reverse after  ->  plain = reversed(b[i] ^ ((key + i) & 255))
```

**Time Trial: peeling in bytecode.** The chain was `Util.mixLayer…` → `LayerKit.peelStack…` → `PeelStack.mixStack…`
→ `Mix.f1` → `Util.finPeel…` ^ const. The peel step, from the hand port `check_tt30.py`:

```python
def peelStack(j):
    j2 = 0
    for i in range(8):                                   # per-byte xor with 4+i
        j2 |= (((j >> (i * 8)) & 255) ^ ((4 + i) & 255)) << (i * 8)
    j3 = 0
    for i in range(8):                                   # byte reverse
        j3 = ((j3 << 8) & M) | ((j2 >> (i * 8)) & 255)
    return (j3 + layeredGate(j3 & 255, (j3 >> 8) & 255, (j3 >> 16) & 255) * C) & M

def layeredGate(a, b, c):
    return ((a ^ b) + c) % 31
```

The `seal*` methods are uncalled decoys, as always. `dalvik.py` and `check_tt30.py` agreed before the submit:
`CORRECT`.

## Time Trial & Mastery
- All timed modes were regular untimed attempts. Time Trial `uar` 32.
- Mastery: `mobmap29.py` verified 14/14 set ↔ package mappings. Computed in 5–7 s and submitted once: `CORRECT`.

## Lessons / gotchas
- On consecutive days (29 and 30) a v1 codec shipped without an encoder. The approach that worked both times was
  to enumerate a small family of transforms and accept only a *unique* match against the strict answer pattern.
- Prompt words ("native indirection", "integrity checks") don't guarantee those features are in the build. The
  interpreter's call trace shows what the code actually does.
