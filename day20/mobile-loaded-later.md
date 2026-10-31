# 📱 Loaded Later

| | |
|---|---|
| **Day** | 20 |
| **Lane** | 📱 Mobile Android |
| **Challenge ID** | `mobile-android-day-20-loaded-later` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day20_quick/mob20.py`](../solvers/day20_quick/mob20.py) |

## Prompt
> Analyze a challenge-signed secondary DEX and recover the module contract.

## TL;DR
New codec **`dynamic`**: `{"codec":"dynamic","data":"assets/payload.dex"}`. Here `data` is not an encoding. It is the
APK member path of a **secondary DEX** (508 bytes, the "challenge-signed module"). Its only class,
`com.huntress.arena.payload.Module`, declares `public static final String ANSWER = "ANS-…"` and
`CONTRACT = "DAY20-SIGNED-MODULE:secondary DEX loading"`. `mob20.py` reads the static field values straight from
the DEX `class_def` `static_values` array. Nothing is decompiled or executed.

## Artifact
- `assets/huntress_puzzle.json` points at `assets/payload.dex`.
- `assets/payload.dex`: one class, `Module`, with two `static final String` fields.
- `classes.dex`: the usual stub (`LoadedLater` constants `CODEC="dynamic"`, `CONTROL="dynamic_dex"`, and
  `ChallengeActivity` WebView pointing at the `127.0.0.1:19090` decoy).
- Mastery: 5 sets via `delivery=1..4`, with codecs `reverse`, `base64`, `xor`, `xor`, `dynamic`.

## Solution
**Theme.** Dynamic code loading (`DexClassLoader`, `InMemoryDexClassLoader`, `PathClassLoader` over a downloaded or
asset-shipped DEX) hides logic from static scanners of `classes.dex`. If the loaded module isn't integrity-checked,
it can also be swapped out. "Recover the module contract" means reading what the module promises to provide.

**Extraction.** A `static final String` constant in a DEX is stored in the class's `static_values_off`
`encoded_array`, as `VALUE_STRING` (type `0x17`) entries indexing the string table:

```python
cls_idx, _acc, _sup, _ifs, _src, _ann, cdata, svals = struct.unpack_from("<8I", b, co + 32 * i)
# class_data: static field list -> names (field_ids[k].name_idx -> string table)
cnt, p = uleb(b, svals)
for _ in range(cnt):
    h = b[p]; p += 1
    vt, va = h & 0x1f, h >> 5
    if vt == 0x17:                                           # VALUE_STRING
        idx = int.from_bytes(b[p:p + va + 1], "little"); p += va + 1
        vals.append(strings[idx])
# zip(static field names, vals) -> {"ANSWER": "ANS-…", "CONTRACT": "DAY20-SIGNED-MODULE:…"}
```

The solver prefers the field named `ANSWER`. Otherwise it takes the unique `ANS-` string in the module. Before
parsing, `unwrap()` handles gzip, a ZIP/JAR holding `classes.dex`, Base64, or an XOR `key`, in case a variant wraps
the module. It prints the whole static-string map for review, and jadx (absolute paths) was used only to confirm.

## Time Trial & Mastery
- All timed modes in all three quick lanes were regular untimed attempts (`deadline: None`, `run_for_time: false`).
- Time Trial `uar` 32. All three modes were `CORRECT` on the first submit.

## Lessons / gotchas
- Static DEX parsing (string table + `static_values`) is enough for constants. Don't run a decompiler or a VM when a
  table lookup answers the question.
- The theme came back on [Day 31](../day31/mobile-mobile-arena-gauntlet.md) as v2 *code*. There the main DEX loads
  `payload.dex` through `InMemoryDexClassLoader` and calls `share(long)` reflectively, so the interpreter needed a
  class-loader model.
