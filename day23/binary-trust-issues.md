# ⚙️ Trust Issues

| | |
|---|---|
| **Day** | 23 |
| **Lane** | ⚙️ Binary Reverse Engineering |
| **Challenge ID** | `binary-reverse-engineering-day-23-anti-analysis-recognition` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day23_binary/b23.py`](../solvers/day23_binary/b23.py) · [`inspect23.py`](../solvers/day23_binary/inspect23.py) |

## Prompt
> This binary doesn't trust you. It checks the clock, sniffs the environment, and takes different branches when it thinks it's being watched. Spot every predicate and force the truth out.

## TL;DR
Day-22 contract (264 questions) plus a 12-question `d23` unit: a **VB.NET .NET 8 assembly** with its
runtimeconfig. Same shape as the F# unit, plus one new field, `xor_key_hex`. The anti-analysis predicates
from the prompt are real and were read with ILSpy for the record, but nothing about them is graded. The
Day-22 handler was generalized into a prefix-parameterized `managed_fields()`, and all three modes passed on
the first submit.

## Artifact
WinZip-AES ZIP (password `infected`). New members in ZIP order: `d23--sample.dll` (8,060 B, VB.NET, `pe_cli`,
machine `0x14c`, namespace `Huntress.Binary.Day23`, module `Program`) and `d23--sample.runtimeconfig.json`
(98 B, `net8.0`). No dependency DLL this time.

Fields: `d23_artifact_sha256_{1,2}`, `d23_analysis_{format,machine,metadata_version}`,
`d23_analysis_config_{campaign,domain,mutex,url,crc32_hex}`, `d23_analysis_hcfg_version` and the new
**`d23_analysis_xor_key_hex`**.

## Solution
**What the program does** (decompiled `Main()`, never executed):
- reads `HUNTRESS_HOST_MODEL` (default `workstation`);
- times a 128-iteration XOR loop with a `Stopwatch`;
- `analysis_detected = Debugger.IsAttached || ProcessorCount < 2 || ElapsedTicks > Int64.MaxValue - 1`
  (the tick predicate can never fire);
- then forces the result: false for `workstation`, true for `analysis` / `sandbox`, and false for anything
  else via the `switch` default;
- branch = success / decoy / failure, with event counts 47 / 30 / 25 / 1, printed as a
  `huntress.binary.dynamic_trace.v1` JSON (`vbnet_anti_analysis_predicate_trace`, `inert_predicate_only`).

**What is graded.** The primary DLL holds exactly one HCFG record, appended after `.reloc` at the end of
the file (offset 7680 in variant 000: 7680 + 12 + 368 = 8060). It is raw (not Base64, not UTF-16) and
CRC32-valid; no decoys appeared in the nine variants seen.

| Field | Value |
|---|---|
| `format` / `machine` | `pe_cli` / `i386` |
| `metadata_version` | `v4.0.30319` |
| `config_*` | from the decoded JSON |
| `config_crc32_hex` | header bytes 8–11 as `0x%08x` |
| `hcfg_version` | `1` |
| `xor_key_hex` | header byte 5 as `0x%02x` (e.g. `0x81`, `0x68`, `0x09` across variants) |

`managed_fields(d, fl, diag)` now takes the unit prefix as a parameter and emits the superset of managed
fields (including `xor_key_hex` and `hcfg_offset`); any key not in the day's contract is dropped at submit
time.

## Time Trial & Mastery
`deadline: None` again (regular untimed play); 64 unique attempts for time trial, 16 for mastery.

| Mode | Questions | Time used |
|---|---|---|
| single_solve | 276 | untimed, one submit |
| time_trial | 276 | 5.4 s end to end |
| mastery | 1932 (**7 sets** × 276) | 12.7 s end to end (gather 9.5 s) |

## Lessons / gotchas
- Diff the new question ids against the previous unit of the same family; here the delta was a single
  `xor_key_hex` field.
- Write handlers that emit a superset of fields and filter by the contract at submit time. Later days can
  add fields to old units without code changes.
- Anti-analysis logic can be read statically (ILSpy) without running anything; here it was context only.
