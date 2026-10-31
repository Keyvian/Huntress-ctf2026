# ⚙️ Zig Zag

| | |
|---|---|
| **Day** | 10 |
| **Lane** | ⚙️ Binary Reverse Engineering |
| **Challenge ID** | `binary-reverse-engineering-day-10-zig-cross-platform-services` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day10_binary/b10.py`](../solvers/day10_binary/b10.py) · [`d10start.py`](../solvers/day10_binary/d10start.py) |

## Prompt
> Zig promises one binary for every platform. Compare the ELF and PE service descriptors side by side and prove they're the same program wearing different uniforms.

## TL;DR
Day-9 contract (90 questions) plus a 10-question `d10` unit: a Zig service binary that is **ELF in some
variants and a native PE `.exe` in others**. Its config is a raw HCFG record in a dedicated section named
`.hcfg`, present in both containers. The new field `has_hcfg_section` is just "does a section called
`.hcfg` exist". This was the first day solved by the scheduled parallel headless agents; all lanes of the day finished
in about six minutes.

## Artifact
One WinZip-AES ZIP (password `infected`) for single solve and time trial; mastery has three sets (default
delivery = set 1, `delivery=1,2` = sets 2 and 3, answer ids `setN.<id>`). The `d10` binary has a Zig/LLD
`.comment`; the ELF build is stripped and dynamically linked. The PE build's section list is `.text .rdata
.buildid .data .pdata .hcfg .tls .rsrc .reloc`.

`d10` fields: `artifact_sha256_1`, `format`, `architecture`, `machine`, `config_{campaign,domain,mutex,url}`,
`config_crc32_hex`, `has_hcfg_section`.

## Solution
- `format`: from the magic bytes, `elf` or `pe`.
- `architecture`: `x86-64`.
- `machine`: the **integer** machine value of whichever header the file has: ELF `e_machine` = `62`,
  COFF `Machine` = `34404` (`0x8664`).
- `has_hcfg_section`: `true` if a section named `.hcfg` exists. ELF names come from pyelftools; PE names
  are the 8-byte section-table names with NULs stripped.
- Config: the raw HCFG record inside `.hcfg`. The full header is now explicit:
  `HCFG` + version (byte 4) + XOR key (byte 5) + LE16 size (bytes 6–7) + **LE32 CRC32 of the decoded JSON**
  (bytes 8–11), then the JSON XOR'd with the key from byte 12. The computed CRC equals the stored one,
  which makes a handy validity check.
- The JSON has more keys than are asked: `campaign`, `domain`, `ipv4`, `url`, `mutex`, `windows_path`,
  `linux_path`, `service`, `host_model` (e.g. `BR10-000`, `node-000.day10.example.invalid`,
  `Global\HuntressBR10_000`).

Units `d01`–`d09` were unchanged from [Day 9](../day09/binary-nimble.md).

**Workflow.** Diff the question ids against the previous day, write the one new handler, and in single
solve **bank the new unit's subset first**. Here the 10 `d10` answers came back `accepted` with 90
remaining, and the other 90 then finished it.

## Time Trial & Mastery
`b10.py --save <dir> --submit --split-on-fail` does start → parallel delivery fetch → compute → submit in
one process. If a full submit is rejected, `--split-on-fail` re-submits per `(set, dNN)` group to isolate
the wrong unit without losing the rest.

| Mode | Questions | Time used / window |
|---|---|---|
| single_solve | 100 | untimed |
| time_trial | 100 | 3.8 s / 16 s, one shot |
| mastery | 300 (3 × 100) | 5.3 s / 28 s, one shot (set 2's `d10` was the PE build) |

## Lessons / gotchas
- "Same program in different uniforms" means the same config in an ELF or a PE. Make `format`, `machine`
  and section listing container-agnostic.
- Machine is an integer for every unit from Day 8 on, so a PE build answers `34404`, not `x86-64`.
- The `.hcfg` section reappears on Day 14 (Objective-C) and becomes the `raw_hcfg_section` storage label on
  [Day 17](../day17/binary-decoder-ring.md).
