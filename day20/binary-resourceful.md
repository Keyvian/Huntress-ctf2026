# ⚙️ Resourceful

| | |
|---|---|
| **Day** | 20 |
| **Lane** | ⚙️ Binary Reverse Engineering |
| **Challenge ID** | `binary-reverse-engineering-day-20-resources-and-overlays` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day20_binary/b20.py`](../solvers/day20_binary/b20.py) |

## Prompt
> Binaries have attics: resources, overlays, bytes past the end of the sections. Rummage through this one's hidden storage and map every boundary.

## TL;DR
Day-19 contract plus a 12-question `d20` unit: a GHC-compiled Haskell ELF with an **`RS20` resource
overlay** after the section-header table. This time nothing is packed: the overlay holds a plain HCFG
record followed by a "scratch" trailer whose SHA-256 is in the header. The solver checks that the header's
lengths end exactly at the end of the file, verifies the hash, and takes the only CRC-valid HCFG record.

## Artifact
WinZip-AES ZIP (password `infected`). New member `d20--variant-NNN.elf` (1,201,351 bytes, 33 sections, a
`.symtab` and `.debug-ghc-link-info`). `e_shoff` 1198776 + 33 × 64 = 1200888 = start of the overlay; the
overlay is 463 bytes.

New fields: `d20_artifact_sha256_1`, `d20_analysis_{format,architecture,machine}`,
`d20_analysis_config_{campaign,domain,mutex,url,crc32_hex}`, `d20_analysis_hcfg_version`,
`d20_analysis_overlay_offset`, and the new kind **`d20_analysis_hcfg_resource_size`**. The `format`
question became an enum: `elf`, `pe`, `pe_cli`, `jar`, `wasm`, `neko_bytecode` (the answer was `elf`).

## Solution
Overlay layout, as given in the question:

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `RS20` |
| 4 | 4 | u32le `1` |
| 8 | 4 | HCFG resource length, u32le (380) |
| 12 | 2 | scratch length, u16le (35) |
| 14 | 2 | padding |
| 16 | 32 | SHA-256 of the scratch bytes |
| 48 | rlen | HCFG resource |
| 48 + rlen | slen | scratch text, `private-scratch:BR20-NNN:inert-only` |

Checks used by `d20_fields()`: `o + 48 + rlen + slen == len(member)`, the scratch SHA-256 matches, and the
resource contains exactly one HCFG record whose stored CRC (bytes 8–11) equals the computed CRC32. The
question asked for "the unique CRC32-valid HCFG record", so the filter matters even though no decoys
appeared.

- `overlay_offset` = offset of the **final** `RS20` magic (1200888 in all seven variants seen).
- `hcfg_resource_size` = the u32le at +8 (380).
- `config_crc32_hex` = HCFG header bytes 8–11 as `0x%08x`.
- `format` `elf`, `architecture` `x86-64`, `machine` `62`, `hcfg_version` `1`.

`fmt_of(b, cli=True)` now returns `pe_cli` for a PE with a CLR data directory and `neko_bytecode` for the
`NEKO` magic, so it can answer the enum for any unit. (Neko bytecode shows up as the
[Day-30](../day30/binary-campaign-trail.md) unit.)

## Time Trial & Mastery
Both timed modes again came up with `deadline: None` (regular play; `run_for_time` was not requested).

| Mode | Questions | Time used |
|---|---|---|
| single_solve | 240 | untimed, one submit |
| time_trial | 240 | 4.3 s end to end |
| mastery | 1200 (5 sets × 240) | 10.1 s end to end; ~32 MB per delivery, parallel gather ~7.7 s |

## Lessons / gotchas
- "Map every boundary" became concrete checks: section-header end = overlay start, and the header's
  lengths must end exactly at the end of the file.
- When the question says "unique CRC32-valid record", implement the uniqueness and the CRC check, not just
  "first match".
- Read the format enum. It listed `neko_bytecode` ten days before a Neko unit appeared.
