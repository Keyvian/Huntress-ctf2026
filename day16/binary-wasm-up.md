# ⚙️ Wasm Up

| | |
|---|---|
| **Day** | 16 |
| **Lane** | ⚙️ Binary Reverse Engineering |
| **Challenge ID** | `binary-reverse-engineering-day-16-webassembly-optimization-equivalence` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day16_binary/b16.py`](../solvers/day16_binary/b16.py) |

## Prompt
> WebAssembly runs in a sandbox, but the sandbox has doors: imports, memory, indirect calls. Map every door in this module and inventory what passes through.

## TL;DR
Day-15 contract plus a 10-question `d16` unit: a **pair of tiny WebAssembly modules** (about 570 bytes
each), one "direct" and one "compact" build of the same function. Each module's data section holds the same
raw HCFG record, which the existing scanner decodes unchanged. The new labels were `wasm` (format) and
`wasm32` (architecture), both accepted on the first try.

## Artifact
WinZip-AES ZIP (password `infected`). New members, in ZIP order: `d16--variant-NNN-direct.wasm` (570 B) and
`d16--variant-NNN-compact.wasm` (561 B).

A 20-line LEB128 section walker was enough to read them:
- sections: type (one `(i32) -> i32`), function, memory (1 page), export (`memory`, `evaluate`), code, data;
- **no** import, table or element section, despite the prompt's "imports … indirect calls";
- the two code bodies compute the same thing (`evaluate(x)` = 33, 17, 12 or 1 for x = 0, 1, 2 or anything
  else). The direct build uses a nested `if/else` chain, the compact one three `select`s. That is the
  "optimization equivalence" in the challenge id; nothing asks about it.
- each data section holds the raw HCFG record (offset 125 in the direct module, 116 in the compact one),
  plus the strings `huntress.binary.dynamic_trace.v1` and `sandboxed_module_inventory`.

## Solution
| Field | Value |
|---|---|
| `d16_artifact_sha256_1` / `_2` | SHA-256 of the direct / compact module (ZIP order) |
| `d16_analysis_{direct,compact}_format` | `wasm` |
| `d16_analysis_{direct,compact}_architecture` | `wasm32` |
| `d16_analysis_compact_config_{campaign,domain,mutex,url}` | from the HCFG JSON (`BR16-000`, …) |

No machine, CRC, XOR-key or direct-config fields were asked on this day.

`b16.py` changes: `fmt_of` returns `wasm` for the `\0asm` magic, `arch_of` returns `wasm32`, `machine_int`
returns `none`, and the Day-15 pair logic became a generic `pair_fields()` shared by `d15` (ELF pair) and
`d16` (wasm pair). The labels can be overridden with the `WASM_FMT` / `WASM_ARCH` environment variables
for probing, but no probing was needed. Single solve banked `d16` in four groups (sha pair, format pair,
architecture pair, the four compact config fields), then the rest.

## Time Trial & Mastery
`deadline` was null in all start responses; no rate limiting.

| Mode | Questions | Time used |
|---|---|---|
| time_trial | 160 | 4.6 s end to end, one shot |
| mastery | 800 (5 × 160) | 9.9 s end to end, one shot |

## Lessons / gotchas
- A new container format only needs new `format`/`architecture` labels if the config carrier is unchanged.
  Bank those labels separately in single solve before the timed modes.
- `wasmtime` was installed but not needed, and a WebAssembly parsing package did not import on Python
  3.14. For this kind of question, a hand-written section walker is faster to trust.
