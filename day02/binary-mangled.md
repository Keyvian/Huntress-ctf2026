# ⚙️ Mangled

| | |
|---|---|
| **Day** | 02 |
| **Lane** | ⚙️ Binary Reverse Engineering |
| **Challenge ID** | `binary-reverse-engineering-day-02-cpp-and-pe-orientation` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/solve_mangled.py`](../solvers/solve_mangled.py) |

## Prompt
> C++ on Windows. The symbols are mangled, the classes hide behind vtables, and RTTI is your Rosetta Stone. Demangle it all with `c++filt`, reconstruct the classes, and don't forget the PE imports.

## TL;DR
Each bundle pairs a plain C ELF (the Day-1 fields again) with a C++ binary that is **ELF or PE depending on
the attempt**. The C++ binary carries mangled vtable/typeinfo symbols and an XOR-encoded `HCFG`
configuration blob. Find the blob, brute-force the one-byte key by looking for `"campaign"` in the output,
parse the JSON, and report the symbol names in the exact form the container stores them.

## Artifact
A WinZip-AES ZIP (password `infected`; open it with `pyzipper`) with two members: the C ELF and the C++
binary. Fields:

| Group | Fields |
|---|---|
| C binary | `c_sha256`, `c_machine`, `c_has_symtab`, `c_marker`, `c_recover_code` |
| C++ binary | `cpp_sha256`, `cpp_format` (`elf` / `pe`), `has_cpp_vtable`, `has_cpp_typeinfo`, `vtable_symbol`, `mangled_score_symbol` |
| C++ config | `cpp_xor_key`, `campaign`, `domain`, `url`, `mutex`, `cpp_config_crc32` |

## Solution
**Telling the two members apart.** The C++ member is the one whose `nm` output or bytes contain `_ZTV` /
`_ZN`; the other is the C binary. The C fields reuse the [Day 1](../day01/binary-elf-aware.md) logic
(`.huntress` marker, `recover_code` immediate in decimal, `.symtab` presence).

**Format.** `cpp_format` is the lowercase container family taken from the magic bytes: `\x7fELF` → `elf`,
`MZ` → `pe`.

**Symbols.** Collect mangled names from `nm` and from a raw byte regex (`[.\w$]*_Z[A-Za-z0-9_$]+`), drop
the C++ runtime (`__cxxabiv1`, `St9type_info`), then pick:
- `vtable_symbol`: a user `_ZTV…` name;
- `mangled_score_symbol`: the mangled method whose name contains `score` (a `_ZNK…5scoreE…` const method).

The container changes the spelling. ELF stores bare names (`_ZNK…score…`, `_ZTV…`). The MinGW PE stores
**COMDAT-decorated section names**: `.text$_ZNK…score…` and `.rdata$_ZTV…`. On PE, the accepted answer was
the decorated form, so the picker prefers a `.text$` / `.rdata$` prefix when present and the bare name
otherwise.

**The HCFG config.** The configuration is a small binary record that starts with the ASCII magic `HCFG`,
followed by a JSON object XOR-encoded with a single-byte key (keys `0x31` and `0x32` were seen). This
solver did not parse the header yet. It took the 2 KB after each `HCFG` hit, tried every key 1–255 and
kept the one whose output contains both `"campaign"` and `"domain"`, then cut out the balanced `{…}`.
(Day 3 documents the header properly; see [Table Manners](../day03/binary-table-manners.md).)

```python
for k in range(1, 256):
    dec = bytes(x ^ k for x in region)
    if b'"campaign"' in dec and b'"domain"' in dec:
        ...  # slice the balanced JSON object out of dec
```

- `campaign`, `domain`, `url`, `mutex`: the JSON values verbatim.
- `cpp_config_crc32`: `0x%08x` of `zlib.crc32` over the decoded JSON bytes.
- `cpp_xor_key`: the key as hex with a `0x` prefix.

## Time Trial & Mastery
Same solver. Mastery answer ids are `set{N}.<field>`, and set N is fetched from `delivery = N − 1`. If a
full submit was not CORRECT, the solver fell back to submitting each field alone: correct answers bank
(`accepted` + `remaining`), wrong ones come back `incorrect`, which isolates the bad field without losing
the good ones.

## Lessons / gotchas
- The C++ member can be ELF in one attempt and PE in the next. Detect the format from the bytes every time.
- Symbol answers follow the container's own spelling. PE/COFF from MinGW stores COMDAT section names
  (`.text$…`, `.rdata$…`), and that decorated string was the accepted value.
- CRC32 is computed over the decoded JSON, not over the encoded blob.
- The HCFG record introduced here becomes the backbone of the whole lane: almost every later unit hides its
  configuration in an HCFG record (raw, Base64-wrapped, in a dedicated section, or inside an overlay).
