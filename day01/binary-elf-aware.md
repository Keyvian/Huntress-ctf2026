# ⚙️ ELF Aware

| | |
|---|---|
| **Day** | 01 |
| **Lane** | ⚙️ Binary Reverse Engineering |
| **Challenge ID** | `binary-reverse-engineering-day-01-c-elf-orientation` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/solve_elf.py`](../solvers/solve_elf.py) |

## Prompt
> Before you can reverse anything, you have to learn to read. These plain C binaries are your primer: headers, section tables, symbol tables. Start with `readelf -h -S` and work your way down.

## TL;DR
Small, plain C ELF binaries. Every answer is a header, section or symbol fact that `readelf`, `nm` and
`objdump` print directly, plus one tiny disassembly: the constant returned by a function literally named
`recover_code`. The difficulty was all in the answer *shape* (exact label spellings, decimal immediates) and
in the time-trial bundle, which mixes the real binary with decoys that have different symbol tables.

## Artifact
A ZIP of ELF64 x86-64 executables built from C. The time-trial bundle holds four binaries ("slots"), and the
mastery bundle nests one such bundle per set. Some slots are decoys: a "section beacon" build with an
`inspect_section` function and a stripped build with no symbols.

Answer ids are per binary, not global. The generic question list looks like one set of fields, but the
real `answer_ids` are `slot0_…` to `slot3_…` in time trial (36 answers) and `set{N}.slot{M}_…` in mastery
(up to 72). Each slot has nine fields:

| Field | Source | Example shape |
|---|---|---|
| `elf_class` | `e_ident[EI_CLASS]` | `ELF64` |
| `endianness` | `e_ident[EI_DATA]` | `little` |
| `machine` | `e_machine` | `x86-64` |
| `elf_type` | `e_type` | `ET_EXEC` |
| `entry_point` | `e_entry` | `0x401040` |
| `marker` | NUL-terminated string in the custom `.huntress` section | `none` if absent |
| `has_symtab` | a `.symtab` section exists | `true` / `false` |
| `exported_symbol` | first user global `T` symbol from `nm` (not CRT, not `main`) | `none` if absent |
| `recover_code` | the integer that `recover_code` returns | `none` if the function is absent |

## Solution
1. Unpack the bundle and keep only members whose first bytes are `\x7fELF`.
2. Read the header with `struct` (offsets 4, 5, 16, 18 and 24 in ELF64) and map `e_machine`/`e_type`
   through small tables (`62 → x86-64`, `2 → ET_EXEC`).
3. `readelf -S -W` tells whether `.symtab` exists; `readelf -x .huntress` dumps the marker section.
4. `nm` lists the global text symbols. Drop the CRT names (`_start`, `_init`, `frame_dummy`,
   `__libc_csu_init`, …) and `main`; the first remaining `T` symbol is the exported user function.
5. `objdump -d -M intel` and look only inside `<recover_code>:`. The body is `mov eax, imm32; ret`, and the
   answer is the immediate **in decimal** (e.g. `0x1fa4` → `8100`).

```python
dis = run("objdump", "-d", "-M", "intel", path)
mm = re.search(r"<recover_code>:(.*?)(?:\n\n|\Z)", dis, re.S)
if mm:
    m2 = re.search(r"mov\s+eax,0x([0-9a-fA-F]+)", mm.group(1))
    recover = str(int(m2.group(1), 16)) if m2 else "none"
```

The `recover_code` and disassembly conventions set here (function located through `.symtab`, decimal
immediate, Intel syntax) survive unchanged into the cumulative `d01` unit of every later day.

## Time Trial & Mastery
The same solver handles all modes. It parses each answer id into `(set, slot, field)`, fetches every
delivery up front (mastery sets map to `delivery = set − 1`), extracts the ELF members, computes facts once
per unique binary (deduplicated by SHA-256) and submits everything in one request. Slots are matched to
binaries by name (`slot-N.elf`) with a positional fallback.

## Lessons / gotchas
- The question list is a template; trust the `answer_ids`. Each slot is a separate binary with its own facts.
- The main wrong-answer trap was the decoys: a decoy has its own constant in an `inspect_section` function.
  `recover_code` must come from a function *named* `recover_code`, and is `none` when no such symbol exists.
- `none` is the literal answer for an absent field. Do not leave the field out.
- Immediates are graded in decimal, not hex.
