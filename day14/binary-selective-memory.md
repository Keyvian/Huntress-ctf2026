# ⚙️ Selective Memory

| | |
|---|---|
| **Day** | 14 |
| **Lane** | ⚙️ Binary Reverse Engineering |
| **Challenge ID** | `binary-reverse-engineering-day-14-objective-c-persistence-descriptor` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day14_binary/b14.py`](../solvers/day14_binary/b14.py) · [`peek11.py`](../solvers/day14_binary/peek11.py) |

## Prompt
> Objective-C never forgets: every class, every selector, every string is registered and waiting. Read the persistence descriptor and learn what this binary remembers.

## TL;DR
Day-13 contract plus a 10-question `d14` unit: a small GNUstep-style Objective-C ELF that keeps its raw HCFG
record in a dedicated `.hcfg` section. The questions reuse the `d10` (Zig) shape, `has_hcfg_section`
included, so the change was turning the `d10` handler into a loop over `("d10", "d14")`.

## Artifact
WinZip-AES ZIP (password `infected`), mastery 3 sets. The `d14` binary is a ~17 KB dynamically linked
x86-64 ELF linked with gold, with GNUstep runtime sections (`__objc_selectors`, `__objc_classes`,
`__objc_constant_string`, `__objc_cats`, `__objc_protocols`, …) and a `.hcfg` section at file offset
`0xfa0` = 4000 in every variant seen (000, 002, 004, 007).

## Solution
| Field | Value |
|---|---|
| `artifact_sha256_1` | SHA-256 of the binary |
| `format` / `architecture` / `machine` | `elf` / `x86-64` / `62` |
| `has_hcfg_section` | `true` |
| `config_{campaign,domain,mutex,url}` | `BR14-000`, `node-000.day14.example.invalid`, `Global\HuntressBR14_000`, `https://node-000.day14.example.invalid/api/BR14-000` |
| `config_crc32_hex` | `0x%08x`, equal to the CRC stored in the header |

No `hcfg_offset` or `xor_key_hex` was asked for `d14` on this day.

The "persistence descriptor" in the prompt is an Objective-C `TriggerDescriptor` class with a
`triggerName` property and the selectors `initWithTrigger:` and `eventCountForModel:`, plus strings such as
`UserLogin`, `HUNTRESS_HOST_MODEL`, `workstation`, `analysis`, `sandbox` and a
`huntress.binary.dynamic_trace.v1` template (`non_mutating_trigger_plan`). It is flavor; nothing about it is
graded.

## Time Trial & Mastery
The windows were back to 30 s.

| Mode | Questions | Time used / window |
|---|---|---|
| single_solve | 140 | untimed (`d14` subset banked first, 130 remaining, then the rest) |
| time_trial | 140 | 3.3 s / 30 s, one shot |
| mastery | 420 (3 × 140) | 5.7 s / 30 s, one shot |

Mastery set 2 again mixed in PE builds of `d02`, `d04` and `d10`.

## Lessons / gotchas
- By this point every new unit reused one of two contracts: the `d09` one (Base64 `SENG` literal +
  `hcfg_offset`) or the `d10` one (`.hcfg` section + `has_hcfg_section`). Diffing the new ids against the
  existing handlers took seconds.
- On [Day 17](../day17/binary-decoder-ring.md), the storage label for this exact layout (raw record in a
  dedicated `.hcfg` section) turned out to be `raw_hcfg_section`, the second of the two blocking labels.
