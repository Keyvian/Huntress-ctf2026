# ⚙️ Flow State

| | |
|---|---|
| **Day** | 18 |
| **Lane** | ⚙️ Binary Reverse Engineering |
| **Challenge ID** | `binary-reverse-engineering-day-18-control-flow-reconstruction` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day18_binary/b18.py`](../solvers/day18_binary/b18.py) |

## Prompt
> Follow the calls and the program tells you its story. Reconstruct the call graph, read the API intent at each edge, and prove no injection hides in the flow.

## TL;DR
Day-17 contract (204 questions, including the now-documented `hcfg_storage` enum) plus a 12-question `d18`
unit: a gfortran ELF with a raw HCFG record in `.rodata`. The fields have exactly the `d17` shape, so the
whole solver change was adding `"d18"` to the raw/Base64 HCFG loop. All three modes passed on the first
submit. The call-graph story in the prompt is real in the binary, but no question asks about it.

## Artifact
WinZip-AES ZIP (password `infected`), new member `d18--variant-NNN.elf` (16,544 bytes, dynamically linked
against `libgfortran.so.5`, not stripped).

What the program does (for the record): `MAIN__` reads the environment variable `HUNTRESS_HOST_MODEL`,
dispatches with `_gfortran_select_string` over `jumptable.0.5` (`analysis` / `sandbox` / `workstation`) to
one of four tiny stubs (`event_failure.0`, `event_sandbox.1`, `event_decoy.2`, `event_success.3`) through an
indirect `call rax`, folds the config bytes into a checksum with an unreachable comparison branch, then
prints a `huntress.binary.dynamic_trace.v1` JSON trace (`family: fortran_indirect_flow_trace`,
`effects: modeled_process_access_no_injection`). That plaintext JSON in `.rodata` is a distractor.

## Solution
The graded config is the `.rodata` object `encoded_config.4` (379 bytes) at file offset **8512**
(`0x2140`): `HCFG`, version 1, XOR key (`0x31` in the single variant), LE16 size 367, LE32 CRC32 of the
plaintext, then the XOR'd JSON with `campaign`, `domain`, `ipv4`, `url`, `mutex`, `windows_path`,
`linux_path`, `service` and `host_model`.

| Field | Value |
|---|---|
| `d18_artifact_sha256_1` | SHA-256 of the ELF |
| `d18_analysis_{format,architecture,machine}` | `elf`, `x86-64`, `62` |
| `d18_analysis_config_{campaign,domain,mutex,url}` | from the decoded JSON |
| `d18_analysis_config_crc32_hex` | `0x%08x` |
| `d18_analysis_hcfg_offset` | file offset of the `HCFG` magic (`8512`) |
| `d18_analysis_hcfg_version` | `1` |
| `d18_analysis_xor_key_hex` | header byte 5 as `0x%02x` |

No `hcfg_storage` was asked for `d18`.

```python
for d in ("d09", "d11", "d12", "d13", "d17", "d18"):   # raw or Base64 HCFG units, same 12-field shape
    ...
```

## Time Trial & Mastery
Both timed modes reported `unique_attempts_remaining: 0` in the start response, but the start still
succeeded with a real deadline and graded normally.

| Mode | Questions | Time used |
|---|---|---|
| single_solve | 216 | untimed, all 216 in one submit |
| time_trial | 216 | 4.8 s end to end (deadline 80 s) |
| mastery | 864 (**4 sets** × 216) | 9.3 s end to end (deadline 265 s) |

The solver computes all fields from fresh bytes in about a second after the download.

## Lessons / gotchas
- When a new unit is "one native binary with a raw HCFG in a data section", check its field list against
  the previous unit's and add it to the generic loop.
- The prompt's call graph is real (jump table, indirect call, handler stubs), but it is context, not a
  question. Plaintext JSON traces in `.rodata` are decoys for anyone who greps for `campaign`.
