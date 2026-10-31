# ⚙️ Fraternal Twins

| | |
|---|---|
| **Day** | 29 |
| **Lane** | ⚙️ Binary Reverse Engineering |
| **Challenge ID** | `binary-reverse-engineering-day-29-variant-diffing` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day29_binary/b29.py`](../solvers/day29_binary/b29.py) · [`status0.py`](../solvers/day29_binary/status0.py) · [`qdiff.py`](../solvers/day29_binary/qdiff.py) |

## Prompt
> Two binaries, same source, different compiler moods. Diff the variants, account for every optimization, and prove they're semantically the same program.

## TL;DR
A small delta after Day 28: 14 new `d29_*` questions and no new fields on old units. The unit is a pair of
x86-64 ELFs built from one source at `-O0` and `-O3`. Roles come from the file names, the HCFG record is
found with the backward scan, and the two decoded configs must be byte-for-byte equal. Nothing about the
optimizations is graded. All three modes passed on the first submit.

## Artifact
WinZip-AES ZIP (password `infected`). New members in ZIP order: `d29--sample-O0.elf` and
`d29--sample-O3.elf`, about 43.9 KB each (same size within a set).

Fields: `d29_artifact_sha256_{1,2}`, `d29_analysis_{optimized,unoptimized}_{format,machine}` (`O3.elf` =
optimized, `O0.elf` = unoptimized; `elf` / `62`), the common `d29_analysis_config_{campaign,domain,mutex,url}`
(both payloads must be byte-for-byte equal), and `d29_analysis_optimized_config_{campaign,domain,mutex,url}`
from the O3 member's own record.

## Solution
- Contract diff against Day 28: 392 → 406 ids, 0 gone, 0 changed, 14 new, all `d29_*`. The time-trial
  contract was identical.
- `d29_fields()` picks roles by the stem suffix (`O3` / `O0`, independent of the extension) and flags
  duplicate roles or a config mismatch in its diagnostics.
- HCFG: `hcfg_scan_back()` from [Day 27](../day27/binary-compiler-says-what.md), the first CRC32-valid
  record from the end. Variant 000 has one record per member at offset 43544 (key `0xe1`). Example config:
  `BR29-000`, `variant-000.day29.example.invalid`, `Global\HuntressBR29-000_000`,
  `https://variant-000.day29.example.invalid/v/BR29-000`.
- The decoded payloads were equal in all 15 variants seen (single, time trial and 13 mastery sets), so
  there was no false-friend twist and the optimized config equals the common one.

Note the domain pattern changed (`variant-000.day29…` instead of the earlier `node-000.dayNN…`), which is
why the values are always read from the record and never templated.

## Time Trial & Mastery
| Mode | Questions | Time used |
|---|---|---|
| single_solve | 406 | untimed, one submit |
| time_trial | 406 | 3.4 s end to end (`deadline: None`, 171 unique attempts) |
| mastery | 5278 (**13 sets** × 406) | 27 s end to end (gather 15.4 s; `deadline: None`) |

One transient: the first single-solve download got a JSON response instead of the artifact bytes and the
script crashed while writing it. Re-running reconnected to the same attempt and downloaded normally.

## Lessons / gotchas
- Run the contract diff even after a quiet day: Day 28 grew old units, Day 29 did not.
- If an artifact download returns JSON, re-run; `start` reconnects to the same attempt.
- The only "equivalence" the questions depended on was the byte equality of the two decoded configs; the
  optimization differences themselves were never asked about.
