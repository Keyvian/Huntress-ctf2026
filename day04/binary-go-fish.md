# ⚙️ Go Fish

| | |
|---|---|
| **Day** | 04 |
| **Lane** | ⚙️ Binary Reverse Engineering |
| **Challenge ID** | `binary-reverse-engineering-day-04-go-runtime-fingerprints` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/codex_day4_bin/d4b_solve.py`](../solvers/codex_day4_bin/d4b_solve.py) (single) · [`d4b_timed.py`](../solvers/codex_day4_bin/d4b_timed.py) / [`d4b_final.py`](../solvers/codex_day4_bin/d4b_final.py) (timed) |

## Prompt
> Go binaries are chatty: they ship with build info, function names, and file paths baked right in. Fish them out and map what this one was built to do.

## TL;DR
The first clearly **compounding** day: the Day-3 bundle (`d01` C ELF, `d02` C ELF + HCFG, `d03` .NET
`pe_cli`) comes back unchanged, plus a new `d04` Go ELF with its own XOR'd HCFG config. The Go-specific
part reduces to two labels (`format` = `elf`, `architecture` = `x86-64` even though Go calls it `amd64`) and
one more HCFG decode.

## Artifact
A WinZip-AES ZIP (password `infected`) with `d01--variant-000.elf`, `d02--variant-000.elf`,
`d03--variant-000.dll` + `.runtimeconfig.json`, and `d04--variant-000.elf`. The `d04` binary is a Go
program built with `go1.25.1` (its build info and the usual Go sections such as `.gopclntab` and
`.go.buildinfo` are present), with its config in a raw HCFG record (key `0x51` in the single variant).

New `d04` fields: `artifact_sha256_1`, `architecture`, `format`, `config_{campaign,domain,mutex,url}`,
`config_crc32_hex`.

## Solution
- **d01–d03**: unchanged from [Day 3](../day03/binary-table-manners.md): ELF structure fields, the HCFG
  decode (key at +5, LE16 length at +6, XOR'd JSON at +12, CRC32 over the decoded JSON), and the .NET
  fields `pe_cli` / `i386` / `v4.0.30319`.
- **d04**: run the same `hcfg()` helper on the Go binary.
  - `architecture`: the Go toolchain calls it `amd64`, but the accepted label is **`x86-64`**, the same
    spelling used for ELF `e_machine` everywhere else in the lane.
  - `format`: `elf` (container family, as for d02).

Files are matched to units by the **`dNN-` filename prefix**. The variant numbers after the prefix can differ
inside one bundle, so never match on the full file name.

The single-solve run used the untimed banking behaviour: each field had a short candidate list (e.g.
`["amd64", "x86-64", "x86_64", "AMD x86-64"]` for the architecture), and the solver submitted candidates one
field at a time until one returned `accepted`, then sent the full locked set. The single mode was already
banked/solved by the time the final pass ran, so it produced no fresh flag string.

## Time Trial & Mastery
`d4b_timed.py` / `d4b_final.py` do start → fetch → compute → submit in one process, with only the confirmed
labels as candidates. Mastery answer ids are `set{N}.…`; each set's bundle comes from `delivery = N − 1`
(falling back to the default artifact). `d4b_final.py` checks that every answer id has a computed value
before submitting; when an attempt only partly decoded, it calls `retry` for a fresh variant instead of
submitting an incomplete batch. Both timed modes were solved this way.

## Lessons / gotchas
- Compounding begins here: keep the previous day's solver and add one unit handler.
- Architecture labels follow the lane convention (`x86-64`), not the language's own naming (`amd64`).
- Map files by `dNN-` prefix, never by full name or by archive order alone.
- The same Go unit stays in the bundle as `d04` until the end of the event; on Day 17 it gains
  `has_go_runtime` and `section_names` fields.
