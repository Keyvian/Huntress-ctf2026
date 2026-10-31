# ⚙️ Table Manners

| | |
|---|---|
| **Day** | 03 |
| **Lane** | ⚙️ Binary Reverse Engineering |
| **Challenge ID** | `binary-reverse-engineering-day-03-managed-configuration` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/codex_day3_workdir/table_fast.py`](../solvers/codex_day3_workdir/table_fast.py) (timed, all modes) · [`solvers/codex_day3/solve_table.py`](../solvers/codex_day3/solve_table.py) · probes: [`solvers/d3b_solve.py`](../solvers/d3b_solve.py), [`solvers/full_tm.py`](../solvers/full_tm.py) |

## Prompt
> A .NET binary is a database wearing a trench coat. Read the CLI metadata tables — methods, strings, signatures — and find where the configuration is stashed. `ilspycmd` and `strings` are your friends.

## TL;DR
Three units: `d01` (the Day-1 C ELF, now with section and symbol lists and a disassembly), `d02` (a C ELF
with an XOR'd `HCFG` config), and `d03`, a .NET 8 DLL with its config in a static byte array. 23 of the 24
fields were straightforward. The last one, `d03_analysis_format`, held up the whole lane: the grader wanted
the generator label **`pe_cli`**, a value that appears nowhere in the artifact. It was found by asking a
different model (OpenAI Codex); after that, every mode solved in under 2 seconds per attempt.

## Artifact
A WinZip-AES ZIP (password `infected`) with `d01--variant-000.elf`, `d02--variant-000.elf`,
`d03--variant-000.dll` and `d03--variant-000.runtimeconfig.json` (target framework `net8.0`). 24 answer ids,
8 per unit:

| Unit | Fields |
|---|---|
| `d01` | `artifact_sha256_1`, `elf_class`, `machine`, `elf_type`, `endianness`, `section_names`, `symbols`, `disassembly` |
| `d02` | `artifact_sha256_1`, `format`, `config_{campaign,domain,mutex,url}`, `config_crc32_hex`, `xor_key_hex` |
| `d03` | `artifact_sha256_1` (DLL), `artifact_sha256_2` (runtimeconfig), `format`, `machine`, `metadata_version`, `config_{campaign,domain,mutex}` |

Every question was the same generic template ("What is the exact analysis format value for field
d03_analysis_format in the delivered evidence set?", `exact_text`), with no list of allowed values.

## Solution

### d01: structure
- `elf_class` `ELF64`, `machine` `x86-64`, `elf_type` `ET_EXEC`, `endianness` `little`.
- `section_names`: every section name in header order **including the empty name of section 0**, as
  compact JSON (`json.dumps(x, separators=(",", ":"))`), e.g. `["",".interp",…]`.
- `symbols`: the non-empty names of `.symtab`, in table order, as compact JSON.
- `disassembly`: the instructions of `recover_code` in Intel syntax with a decimal immediate:
  `["mov eax, 8100","ret"]`.

### d02 / d03: the HCFG record
From this day on, the config header is parsed instead of brute-forced:

| Offset | Size | Meaning |
|---|---|---|
| 0 | 4 | ASCII `HCFG` |
| 4 | 1 | version (1) |
| 5 | 1 | XOR key |
| 6 | 2 | payload length, little-endian |
| 8 | 4 | CRC32 of the decoded payload, little-endian |
| 12 | n | JSON payload, XOR'd byte by byte with the key |

```python
p = b.index(b"HCFG"); key = b[p + 5]
size = int.from_bytes(b[p + 6:p + 8], "little")
plain = bytes(x ^ key for x in b[p + 12:p + 12 + size])
cfg = json.loads(plain); crc = zlib.crc32(plain) & 0xffffffff
```

`config_crc32_hex` is `0x%08x` of the CRC over the decoded JSON and `xor_key_hex` is `0x%02x` (keys were
`0x31` for d02 and `0x41` for d03 in the single-solve variant). The JSON has `campaign`, `domain`, `mutex`
and `url` (e.g. `BR03-000`, `node-000.day03.example.invalid`, `Global\HuntressBR03_000`).

In d03, `ilspycmd` (version 9.1.0.7988; the latest release failed on net8 assemblies) shows a static
`Program.Config` byte array of 379 bytes holding the same HCFG record. The program only prints a
synthetic "dynamic trace" JSON (`huntress.binary.dynamic_trace.v1`, network `sinkhole_only`); nothing in it
is graded.

### d03: the managed fields
- `machine`: the COFF machine of an AnyCPU assembly is `0x14c`, answered as `i386`.
- `metadata_version`: the version string of the CLI metadata root. Find `BSJB`, read the u32 length at
  +12, take the string at +16 and strip NULs → `v4.0.30319`.
- `format`: **`pe_cli`**.

### How `pe_cli` was found
`d02_analysis_format` was accepted as `elf`, and on Day 2 the same generator had accepted `elf` / `pe` by
container, so the field was clearly binary-derived. But for the .NET DLL, `pe` was rejected. The team then
rejected, one by one in isolated submits: `pe`, `PE`, `pe32`, `PE32`, `pe32+`, `mz`, `dotnet`, `.net`,
`msil`, `cil`, `il`, `clr`, `managed`, `mono`, `assembly`, `netmodule`, `dll`, `exe`, `coff`, `net8.0`,
`netcoreapp`, `ecma335`, `cli`, `#~`, stash-location words, and many container+runtime compounds
(`pe_dotnet`, `dotnet_pe`, `pe_clr`, `clr_pe`, `pe_managed`, …). Re-submitting each of the other 23 fields
alone confirmed they all banked and that `d03_analysis_format` was the only gap. An organizer replied
that the challenge was working as intended.

The break came from an outside view: OpenAI Codex, asked to reason about the generator's naming, proposed
`pe_cli` (PE container plus CLI metadata). It banked immediately. The taxonomy that holds for the rest of
the event is: native ELF → `elf`, native PE → `pe`, managed .NET PE → `pe_cli`.

## Time Trial & Mastery
The timed windows observed on this day were about **6 seconds**, so `table_fast.py` does everything in one
process: `start` (or `retry`), download, unzip, parse the ELF section and symbol tables directly with
`struct`, decode the HCFG blocks, and submit. Time trial (24 answers) and mastery (48 answers over
`set1.`/`set2.`) both finished in under 2 seconds per attempt. The solver also detects the d02 format from
the magic bytes (`elf` or `pe`), because timed variants can swap the d02 container. Mastery sets come
either from nested zips or from `delivery = N − 1`, and the solver handles both.

## Lessons / gotchas
- When every field but one banks, re-submit each confirmed field alone to prove which one is missing before
  guessing further.
- Some exact-text answers are generator vocabulary, not artifact bytes. These labels tend to be compact
  snake_case compounds (`pe_cli` = container + subtype). See the
  [lane page](../lanes/binary.md#hardest-moments) for the general playbook.
- The organizers later clarified this question. By Day 9 the `d03_analysis_format` question read "identify
  its combined executable-container and managed-runtime format classification … one container_runtime
  token; CLI, CLR, or .NET may name the managed part".
- JSON-array answers must be compact JSON; `section_names` starts with `""`; hex fields need `0x`.
- Use an `ilspycmd` version that matches the target runtime.
