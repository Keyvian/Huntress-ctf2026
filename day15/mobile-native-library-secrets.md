# 📱 Native Library Secrets

| | |
|---|---|
| **Day** | 15 |
| **Lane** | 📱 Mobile Android |
| **Challenge ID** | `mobile-android-day-15-native-library-secrets` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day15_quick/mob15.py`](../solvers/day15_quick/mob15.py) |

## Prompt
> Recover split configuration from DEX and a challenge-owned native library.

## TL;DR
The APK now ships a JNI library, `lib/x86_64/libarena.so`, and the puzzle declares **`codec:"native"`**. The answer
is the string stored in the library's `.symtab` OBJECT symbol `arena_value` (in `.rodata`). The JSON `data`
also carries the same `ANS-` value, so the solver reads the ELF symbol and checks it against the JSON. They matched
every time.

## Artifact
- `assets/huntress_puzzle.json`: `{"codec":"native","data":"ANS-…"}`.
- `lib/x86_64/libarena.so`: a challenge-owned ELF shared object that exports `huntress_arena_secret` and
  `huntress_arena_day`, plus the `.symtab` OBJECT `arena_value`.
- `classes.dex`: the backend URL and `client_secret=SECRET-…` decoy, as on every day.
- Mastery: **5 sets** (catalog: 5 sets / 170 s), mixing codecs `plain`, `caesar`, `split` and `native`.

## Solution
**Theme.** Developers move secrets into `.so` files believing native code is harder to read. A string in
`.rodata`, an exported symbol or a JNI function that returns a constant is one `readelf`/`strings` away. "Split
configuration" means part of the config lives in DEX and part in the native lib.

**Extraction.** The `native` branch reads the symbol by address, with no disassembly needed:

```python
from elftools.elf.elffile import ELFFile
e = ELFFile(io.BytesIO(so_bytes))
for sym in e.get_section_by_name(".symtab").iter_symbols():
    if sym.name == "arena_value" and sym["st_size"]:
        for sec in e.iter_sections():                       # map the VA to a file offset
            a, sz = sec["sh_addr"], sec["sh_size"]
            if sec["sh_type"] != "SHT_NOBITS" and a <= sym["st_value"] < a + sz:
                o = sec["sh_offset"] + sym["st_value"] - a
                val = so_bytes[o:o + sym["st_size"]].split(b"\0")[0].decode("latin1")
```

As a fallback it applies the `ANS-[0-9A-F]{16}` regex to the library bytes. Only libraries containing `huntress_arena`
count as challenge-owned. If the ELF value and the JSON `data` disagree, the solver prints a warning.

## Time Trial & Mastery
- Both timed modes passed on the first submit. Mastery's 5 APKs each carried a different codec, which were
  handled by the existing branches plus `native`.

## Lessons / gotchas
- Cross-check two independent sources when the artifact gives you two. Here both pointed at the same value, which
  confirmed the `native` reading before the first submit.
- This `libarena.so` came back on Day 23 as *code*. The v2 puzzles route a value through
  `Java_…_nativeShare(long)`, and that needed CPU emulation.
