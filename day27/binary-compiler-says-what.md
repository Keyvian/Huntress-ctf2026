# ⚙️ Compiler Says What

| | |
|---|---|
| **Day** | 27 |
| **Lane** | ⚙️ Binary Reverse Engineering |
| **Challenge ID** | `binary-reverse-engineering-day-27-compiler-attribution` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day27_binary/b27.py`](../solvers/day27_binary/b27.py) · [`inspect27.py`](../solvers/day27_binary/inspect27.py) · [`status0.py`](../solvers/day27_binary/status0.py) |

## Prompt
> Every compiler signs its work. Compare the runtime and linker fingerprints across builds and name the toolchain — attribute this binary to its maker.

## TL;DR
Day-26 contract (312 questions) plus a 12-question `d27` unit: **two x86-64 ELF builds of the same program**,
one from GCC and one from TCC (with the TCC runtime linked in). The roles come from the file names, so
"name the toolchain" never became a question. The new piece was the lookup rule: scan **backward from the
end** of each member for a literal HCFG record and take the first CRC32-valid one.

## Artifact
WinZip-AES ZIP (password `infected`). New members in ZIP order: `d27--sample-gcc.elf` (~108 KB) and
`d27--sample-tcc.elf` (~462 KB).

Fields: `d27_artifact_sha256_{1,2}`, `d27_analysis_{gcc,tcc}_format` (`elf`), `d27_analysis_{gcc,tcc}_machine`
(`62`), the common `d27_analysis_config_{campaign,domain,mutex,url}` (both role configs must be byte-for-byte
equal) and `d27_analysis_gcc_config_{campaign,domain}`.

## Solution
- Role by filename suffix (`gcc.elf` / `tcc.elf`); SHA-256 in ZIP order.
- `machine` = `e_machine` in decimal.
- Config: `hcfg_scan_back()` walks `HCFG` occurrences from the end of the member toward the start and
  returns the first record whose length fits, whose CRC32 matches and whose payload is valid JSON (the
  usual raw header: version +4, key +5, LE16 length +6, CRC32 +8, payload +12).
- One record per member, at fixed offsets 107776 (GCC) and 462000 (TCC); no decoys. The two decoded
  payloads were identical in all 13 variants seen, so the common config and the GCC config agree.

Flow: `status0.py` on the base id before starting, `qdiff.py` against the Day-26 contract (0 gone, 0 changed,
12 new; the time-trial contract was identical), write the handler, start single solve with `--save`,
compute offline (324/324 in 1.1 s), cross-check with `inspect27.py`, submit once.

## Time Trial & Mastery
| Mode | Questions | Time used |
|---|---|---|
| single_solve | 324 | untimed, one submit |
| time_trial | 324 | 4.9 s end to end, `deadline: null` |
| mastery | 3564 (**11 sets** × 324) | 30.1 s end to end (gather 23.6 s) |

## Lessons / gotchas
- The lookup direction can change from day to day (forward Base64 constant scan on Days 24–26, backward
  raw scan here). Read the rule from the new question text each time.
- Attribution prompts did not become attribution questions; the role was in the file name.
- Avoid line-editing tools on the solver's huge per-set diagnostic lines; print what you need instead.
