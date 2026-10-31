# ⚙️ Stripped

| | |
|---|---|
| **Day** | 15 |
| **Lane** | ⚙️ Binary Reverse Engineering |
| **Challenge ID** | `binary-reverse-engineering-day-15-assembly-and-symbol-loss` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day15_binary/b15.py`](../solvers/day15_binary/b15.py) · [`peek11.py`](../solvers/day15_binary/peek11.py) |

## Prompt
> No symbols. No names. Just raw assembly and the calling conventions it can't hide. Reconstruct the stripped functions from the instructions alone — the stack never lies.

## TL;DR
Day-14 contract plus a 10-question `d15` unit made of **two files**: the same small ELF once with symbols
and once stripped. Despite the prompt, no question asks about functions or assembly; the fields are
per-file SHA-256, format, architecture and machine, plus two config values. The only things to get right
were the member order behind `sha256_1`/`sha256_2` and the per-role field prefixes. Mastery grew from 3 to
5 sets.

## Artifact
WinZip-AES ZIP (password `infected`). New members `d15--variant-NNN-symbolized.elf` (~16 KB, with
`.symtab`/`.strtab`) and `d15--variant-NNN-stripped.elf` (~14 KB, no symbol table). Both are small dynamic
x86-64 ELFs loaded at `0x400000` and both carry the same dedicated `.hcfg` section with a raw XOR'd HCFG
record (file offset 8461 in variant 000).

## Solution
| Field | Value |
|---|---|
| `d15_artifact_sha256_1` | SHA-256 of the **symbolized** ELF |
| `d15_artifact_sha256_2` | SHA-256 of the **stripped** ELF |
| `d15_analysis_{stripped,symbolized}_format` | `elf` |
| `d15_analysis_{stripped,symbolized}_architecture` | `x86-64` |
| `d15_analysis_{stripped,symbolized}_machine` | `62` |
| `d15_analysis_stripped_config_{campaign,domain}` | from the HCFG JSON, e.g. `BR15-000`, `node-000.day15.example.invalid` |

The sha numbering follows **ZIP order** (symbolized first), not alphabetical order (which would put
`stripped` first). This was confirmed by banking the sha pair on its own in single solve.

`b15.py` adds a `d15` block: hash members in archive order, pick each member's role from a
`stripped`/`symbol` substring in its file name, compute format/architecture/machine per role, and rename
the HCFG config fields into the `d15_analysis_<role>_` prefix. Single solve banked the eight analysis
fields (142 remaining), then the sha pair (140 remaining), then `d01`–`d14` → CORRECT.

## Time Trial & Mastery
The start responses carried `deadline: null`, so no window was visible. `unique_attempts_remaining` was 64
for time trial and 16 for mastery.

| Mode | Questions | Time used |
|---|---|---|
| time_trial | 150 | 4.7 s end to end, one shot |
| mastery | 750 (**5 sets** × 150) | 9.9 s end to end, one shot |

Mastery sets are the default delivery plus `delivery=1..4`. `b15.py` derives the set count from the answer
ids and fetches all deliveries in parallel, so the jump from 3 to 5 sets needed no change. Sets still mixed
PE builds of `d02`, `d04` and `d10`.

## Lessons / gotchas
- For multi-file units, `artifact_sha256_N` follows the archive's member order. Bank the pair separately to
  prove it.
- Choose roles by a filename substring, never by position.
- The prompt promised calling-convention reconstruction; the contract asked for metadata only. Read the
  question list first.
