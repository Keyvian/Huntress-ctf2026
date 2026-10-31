# ⚙️ Decoder Ring

| | |
|---|---|
| **Day** | 17 |
| **Lane** | ⚙️ Binary Reverse Engineering |
| **Challenge ID** | `binary-reverse-engineering-day-17-encoded-configuration-recovery` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | `b17.py` was not preserved; [`solvers/day18_binary/b18.py`](../solvers/day18_binary/b18.py) is `b17.py` plus one line for `d18` and contains every Day-17 handler (see its docstring and `storage_label()`) |

## Prompt
> The configuration is encoded, but the decoder ships with the binary — a ring waiting for its secret. Recover the reversible decoder and read what it was hiding.

## TL;DR
The biggest contract change since Day 8: 204 questions, 44 more than Day 16. Twelve belong to the new `d17`
unit, an Ada (GNAT) ELF with a raw HCFG record; the rest re-enable "deep" fields on the old units `d01`–`d14`.
Every field was computed correctly on the first pass except two **`hcfg_storage`** labels (for `d12` and
`d14`), free-text questions with no vocabulary. 816 candidate tokens were rejected. The lane stayed blocked
from release until an organizer changed the two questions into an enum with a written decision rule; the
answers were `raw_const_array` and `raw_hcfg_section`, and all three modes then finished within the hour.

## Artifact
WinZip-AES ZIP (password `infected`) with the cumulative members `d01`–`d16` plus `d17--variant-000.elf`:
a 1.39 MB x86-64 ELF built with GNAT 14.2.0 (`ada_br17_main.adb`, Ada runtime units such as
`a-textio.adb`, DWARF `.debug_*` sections and a `.symtab`). Its raw HCFG record sits in `.rodata` at file
offset 207432 (XOR key `0x73` in the single variant).

New fields:

| Unit | Fields (example values from the single variant) |
|---|---|
| `d17` | `artifact_sha256_1`, `format` `elf`, `architecture` `x86-64`, `machine` `62`, `config_{campaign,domain,mutex,url}` (`BR17-000`, …), `config_crc32_hex`, `hcfg_offset` `207432`, `hcfg_version` `1`, `xor_key_hex` `0x73` |
| `d01` | `marker` (`.huntress` section string, `BR01-CATALOG-000`), `recover_code` (`8100`) |
| `d02` | `mangled_score_symbol` (`_ZNK15DiscoveryEngine5scoreEPKc`), `typeinfo_symbol` (`_ZTI15DiscoveryEngine`) |
| `d03` | `hcfg_version`, `xor_key_hex` |
| `d04` | `has_go_runtime` (`true`), `section_names` (compact JSON, starting `""`) |
| `d05` | `has_rust_mangled_symbol` (`true`), `section_names` |
| `d06` | `methods` (`["<init>","decodeConfig","campaign","evaluate","main"]`), `access_flags` (`49`) |
| `d07` | `has_coroutine_runtime` (`true`), `method_count` (`7`) |
| `d08`–`d14` | `hcfg_offset` and/or `hcfg_version` where missing, and `hcfg_storage` on `d08`, `d09`, `d11`, `d12`, `d13`, `d14` |

## Solution

### The decodable part
Every field except `hcfg_storage` was computed correctly on the first pass, mostly by reusing code from
the day each unit was introduced:
- `d17` is a native ELF with a raw HCFG record, so it joined the raw/Base64 HCFG loop. `hcfg_offset` = file
  offset of the `HCFG` magic (the [Day-12](../day12/binary-pascal-s-wager.md) convention).
- The deep fields replay the early days: the [Day-1](../day01/binary-elf-aware.md) marker and
  `recover_code`, the [Day-2](../day02/binary-mangled.md) mangled names, the class-file method table for
  [Day 6](../day06/binary-pool-party.md) (`access_flags` 49 = `0x31` = public|final|super) and
  [Day 7](../day07/binary-routine-check.md), and section lists for Go and Rust.
- `hcfg_offset` for the Base64 units is the offset of the `SENG…` text (`d08` Swift: 18366768, `d09`:
  30696, `d11`: 368272, `d13`: 560188); for raw units it is the `HCFG` magic (`d10`: 132160, `d12`:
  82928, `d14`: 4000).

The first submits banked everything except some of the `hcfg_storage` answers. `base64` banked for every
unit whose config is a Base64 `SENG` literal (`d08`, `d09`, `d11`, `d13`). That left `d12` and `d14`:
202/204.

### The blocked part
`hcfg_storage` asked how the record is stored, as `exact_text`: "What is the exact analysis hcfg storage
value for field d12_analysis_hcfg_storage in the delivered evidence set?" No list of values, and `none` was
reserved for absent fields. The two remaining units differ:

| Unit | Language | Where the raw record lives |
|---|---|---|
| `d12` | Free Pascal | raw XOR'd bytes in the standard writable `.data` section, offset 82928 |
| `d14` | Objective-C (GNUstep) | raw XOR'd bytes in a dedicated section named `.hcfg`, offset 4000 (symbol `huntress_config`) |

Using the untimed single-solve attempt as a probe (one candidate per submit, about 1.6 s each, stop at
the first `accepted`), the agent and then an interactive session tried **816 tokens** on both fields: `raw`,
`plain`, `binary`, `bytes`, `byte_array`, `blob`, `xor`, section names (`.data`, `.hcfg`, `section`,
`custom_section`, `named_section`), language words (`typed_constant`, `pascal_const`, `nsdata`,
`objc_const`, `const_char_array`), other encodings (`hex`, `base85`, `identity`), and dozens of compounds
(`section_raw`, `raw_section`, `raw_hcfg`, `raw_byte_array`, `const_array`, `hcfg_section`,
`dedicated_hcfg_section`, …). Every one was `incorrect`. A brief was written so an outside model (as
with `pe_cli` on [Day 3](../day03/binary-table-manners.md)) could propose fresh candidates.

### The fix
Around 12:18 ET the same day an organizer announced in the event chat that two Decoder Ring questions did
have objective answers, but that the Game Master had not said how to submit them, and that the questions
had been fixed. Re-fetching the live question showed `kind: "enum"` with `accepted_values` and a decision
procedure written into the text:

| Token | Rule (applied in order) |
|---|---|
| `base64` | the valid HCFG only appears after decoding a printable Base64 carrier |
| `raw_hcfg_section` | literal `HCFG` begins in a native section named exactly `.hcfg` |
| `wasm_data_segment` | literal `HCFG` is inside a WebAssembly data segment |
| `raw_const_array` | literal `HCFG` begins in a native data section other than `.hcfg` (e.g. writable `.data`) |
| `raw` | any other literal carrier |

`d12` → **`raw_const_array`**, `d14` → **`raw_hcfg_section`**. Both banked and single solve returned
CORRECT. The solver's `storage_label()` now implements the official rule by finding the section that
contains the record's file offset:

```python
if any(h.lower().strip(".") == "hcfg" for h in here):   # sections containing the record offset
    return "raw_hcfg_section"
if here:
    return "raw_const_array"
return "raw"
```

## Time Trial & Mastery
Once single solve was CORRECT, the prerequisite gate opened. Both timed modes started without a visible
deadline and were solved in one process each: 204 answers for time trial and 1020 (5 sets × 204) for
mastery, computed from fresh bytes in about 6–11 s.

## Lessons / gotchas
- The 816 attempts had every piece (`raw_…`, `const_array`, `hcfg_section`) but never the exact joins. Such
  labels are `<category>_<descriptor>` compounds where the descriptor names the observed layout. Enumerate
  the cross-product of a known prefix and artifact-derived descriptors before declaring a token unguessable.
- **Re-fetch the live question** when a field is stuck. Organizers fix graders mid-event, and here the fix
  turned an unguessable field into a deterministic one.
- When everything else is banked, a single-solve attempt is a free probe: one candidate per submit, stop at
  the first `accepted`.
- From the following days on, most new questions spell out their lookup rule in full (see
  [Day 19](../day19/binary-jack-in-the-box.md)), and this kind of block did not happen again in the lane.
