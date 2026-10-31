# 🔎 Little Endian on the Prairie

| | |
|---|---|
| **Day** | 19 |
| **Lane** | 🔎 Metadata Forensics |
| **Challenge ID** | `metadata-forensics-day-19-little-endian-on-the-prairie` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day19_quick/m19.py`](../solvers/day19_quick/m19.py) |

## Prompt
> Linux binaries from several systems have been pooled with Windows executables and renamed data. Determine architecture directly from the ELF header and rebuild deployment groups.

## TL;DR
The new field is `elf.e_machine_u16_hex` for `collector-001.elf`: the `e_machine` field of the ELF header at offset
`0x12`, read in the byte order that `EI_DATA` declares, formatted `0x%04x`. For the x86-64 collector that is
`0x003e`. CORRECT in all three modes.

## Artifact
- `collector-001.elf`: ELF64, little-endian, x86-64 executable, stripped.
- Answer id `d19-elf-001-elf-e-machine-u16-hex`.
- Time Trial: **24 questions**. Mastery: **5 sets × 24 = 120**, one `evidence-0N.zip` per set in the default ZIP. The
  synthesis SHA-256-order question now includes `collector-001.elf`.
- Every variant seen was a single x86-64 ELF. Pooling, renamed data and deployment groups never became questions.

## Solution
```python
assert b[:4] == b"\x7fELF"
cls  = b[4]                       # EI_CLASS: 1 = ELF32, 2 = ELF64
data = b[5]                       # EI_DATA:  1 = little-endian, 2 = big-endian
en   = "<" if data == 1 else ">"
e_type, e_machine = struct.unpack(en + "HH", b[16:20])   # e_machine at 0x12
answer = "0x%04x" % e_machine     # x86-64 = 62 -> "0x003e"
```

`e_machine` is a u16, so the answer is padded to 4 hex digits, the same convention as
[Day 9](../day09/metadata-built-different.md)'s `pe.coff_machine_u16_hex`. The byte order must come from `EI_DATA`:
on a big-endian MIPS or PowerPC binary, a fixed little-endian read gives a byte-swapped value. That is the joke in the
title.

`m19.py` adds a full ELF header reader on top of `m18`:

- `e_ident`: class, endianness, OS ABI.
- `e_type` as `ET_*`, `e_machine` with a name table (x86-64, aarch64, arm, i386, riscv, mips, ppc, …).
- `e_entry`, `e_phoff` / `e_shoff`, `e_flags`, the size and count fields, `e_shstrndx`.

Generic suffixes `_u16_hex`, `_u32_hex`, `_u64_hex` (zero-padded), `_hex` and `_dec` are understood for any of them.
Non-ELF input returns `none`.

## Time Trial & Mastery
All timed modes of all three quick lanes were regular untimed attempts (`deadline: None`). Time Trial CORRECT 24/24,
Mastery CORRECT 120/120.

## Lessons / gotchas
- Read architecture from the header, not the name or extension. The `.elf` suffix here happened to be honest.
- Width-padded hex once more. By now the convention is stable across PE, ELF and (next day) Mach-O fields.
