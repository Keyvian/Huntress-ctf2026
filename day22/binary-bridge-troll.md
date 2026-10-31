# ⚙️ Bridge Troll

| | |
|---|---|
| **Day** | 22 |
| **Lane** | ⚙️ Binary Reverse Engineering |
| **Challenge ID** | `binary-reverse-engineering-day-22-managed-native-bridge` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day22_binary/b22.py`](../solvers/day22_binary/b22.py) · [`inspect22.py`](../solvers/day22_binary/inspect22.py) |

## Prompt
> Managed code on one side, native code on the other, and a bridge of P/Invoke and FFI in between. Pay the troll: trace every crossing and map what goes over.

## TL;DR
Day-21 contract (252 questions) plus a 12-question `d22` unit: an **F# .NET 8 assembly** shipped with its
runtimeconfig and a 5.7 MB `FSharp.Core.dll` dependency. The fields mirror the Day-3 .NET unit (`pe_cli`,
`i386`, metadata version, HCFG config). The only new problem was picking the right DLL when two of them
match "starts with d22-- and ends with .dll". The P/Invoke bridge from the prompt exists, but no question
asks about it.

## Artifact
WinZip-AES ZIP (password `infected`). New members in ZIP order:

| # | Member | Notes |
|---|---|---|
| 1 | `d22--sample.dll` | 18,812 B, the primary F# assembly, `pe_cli`, machine `0x14c` |
| 2 | `d22--sample.runtimeconfig.json` | 98 B, `net8.0` |
| 3 | `d22--FSharp.Core.dll` | 5.7 MB dependency, machine `0xfd1d`, no HCFG |

Fields: `d22_artifact_sha256_{1,2,3}`, `d22_analysis_{format,machine,metadata_version}`,
`d22_analysis_config_{campaign,domain,mutex,url,crc32_hex}`, `d22_analysis_hcfg_version`.

The ImplMap (P/Invoke) rows are `getpid` from `libc` and `GetCurrentProcessId` from `kernel32.dll`. The
solver records them in its diagnostics only.

## Solution
**Picking the primary assembly.** The question says the unit is "the primary managed assembly" and that the
runtimeconfig and dependency DLLs are "delivery support only". `pick_primary_dll()` uses, in order:
1. the `.dll` whose stem equals the `.runtimeconfig.json` stem (`d22--sample`);
2. the unique `.dll` that holds a valid HCFG record;
3. the `.dll` whose name is not a known dependency (`FSharp.Core`, `System.*`, `Microsoft.*`, …).

**Fields** (conventions from [Day 3](../day03/binary-table-manners.md)):
- `format` `pe_cli`, `machine` `i386` (COFF `0x14c`).
- `metadata_version` `v4.0.30319`, from dnfile's metadata root (`pe.net.metadata.struct.Version`, NULs
  stripped), with a raw fallback: find `BSJB`, read the u32 length at +12, take the string at +16.
- Config: the primary DLL holds **two identical CRC32-valid HCFG records**, one inside the body (offset
  15891 in the sample) and one appended at the very end of the file (18432 + 12 + 368 = 18812). The question
  says "accept the first record whose bounds, CRC32 and decoded JSON validate", so `valid_hcfg(dll)[0]`.
  The solver flags it in the diagnostics if the two copies ever differ; they never did in the eight
  variants seen.
- `config_crc32_hex` = header bytes 8–11 as `0x%08x`; `hcfg_version` `1`.

## Time Trial & Mastery
Both timed modes came up with `deadline: None` (regular untimed play; `run_for_time` not requested).
Time trial had 64 unique attempts remaining, mastery 16.

| Mode | Questions | Time used |
|---|---|---|
| single_solve | 264 | untimed, one submit |
| time_trial | 264 | 8.5 s end to end |
| mastery | 1584 (**6 sets** × 264) | 19.8 s end to end; ~35 MB per delivery, parallel gather 16.6 s |

## Lessons / gotchas
- "Starts with `dNN--` and ends with `.dll`" can match a dependency. Tie the primary assembly to its
  runtimeconfig stem.
- Duplicate config copies are possible. Follow the question's "first valid record" rule and check that the
  copies agree.
- The P/Invoke "bridge" was flavor; `inspect22.py` dumps the ImplMap table for anyone curious.
