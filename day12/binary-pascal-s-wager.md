# ⚙️ Pascal's Wager

| | |
|---|---|
| **Day** | 12 |
| **Lane** | ⚙️ Binary Reverse Engineering |
| **Challenge ID** | `binary-reverse-engineering-day-12-pascal-archive-stager` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day12_binary/b12.py`](../solvers/day12_binary/b12.py) · [`peek11.py`](../solvers/day12_binary/peek11.py) |

## Prompt
> Pascal is betting you won't read its record layouts. Take the wager: unpack the archive stager's structures and read the configuration straight from memory's own filing cabinet.

## TL;DR
Day-11 contract plus a 10-question `d12` unit: a Free Pascal (FPC) ELF. Same fields as `d09`/`d11`, but
the HCFG record is **raw** (not Base64) and sits in `.data`, so `hcfg_offset` is the file offset of the
`HCFG` magic itself. About 1.5 minutes for all three modes.

## Artifact
WinZip-AES ZIP (password `infected`), mastery 3 sets. The `d12` binary is a static FPC x86-64 ELF
(`e_machine` 62) with sections `.note.ABI-tag .text .rodata .data .fpcdata .bss .shstrtab` and an RTTI
record name `TBehaviorResult`. Every variant seen (000, 004, 005, 006) had the HCFG at the same file offset,
82928 (`0x143f0`), inside `.data`.

## Solution
| Field | Value |
|---|---|
| `format` / `architecture` / `machine` | `elf` / `x86-64` / `62` |
| `config_{campaign,domain,mutex,url}` | e.g. `BR12-000`, `node-000.day12.example.invalid`, `Global\HuntressBR12_000`, `https://node-000.day12.example.invalid/api/BR12-000` |
| `config_crc32_hex` | `0x%08x` of CRC32 over the decoded JSON |
| `hcfg_offset` | file offset of the raw `HCFG` magic, `82928` |

The `d09`/`d11` handler already collected both Base64 and raw candidates, and for a raw block its `off` is
the file offset of `HCFG`. Adding `"d12"` to the handler tuple was the whole change. The virtual address
was not needed; offsets in this lane are always file offsets.

`.rodata` contains distractors: FPC ansistrings `decoy`, `sandbox`, `failure`, a `"campaign":"` fragment,
and a plaintext `huntress.binary.dynamic_trace.v1` JSON template (`private_scratch_archive_manifest`). None
of them are graded.

Single solve banked the nine non-offset `d12` fields first (111 remaining), then `hcfg_offset` alone (110
remaining) to confirm the offset convention, then everything else.

## Time Trial & Mastery
| Mode | Questions | Time used / window |
|---|---|---|
| time_trial | 120 | 3.1 s / 30 s, one shot |
| mastery | 360 (3 × 120) | 6.4 s / 30 s, one shot |

Mastery set 2 again had PE `.exe` variants of `d02`, `d04` and `d10`, handled by the existing code.

## Lessons / gotchas
- Same field, different carrier: `hcfg_offset` is the offset of whatever the carrier starts with (Base64
  text for `d09`/`d11`, the raw magic here).
- Bank a field whose convention is uncertain on its own, so a wrong guess cannot sink a batch.
- On [Day 17](../day17/binary-decoder-ring.md) this exact placement (a raw record in `.data`) became the
  storage label `raw_const_array`, one of the two labels that blocked the lane for a day.
