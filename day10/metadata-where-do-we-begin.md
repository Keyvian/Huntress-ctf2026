# 🔎 Where Do We Begin?

| | |
|---|---|
| **Day** | 10 |
| **Lane** | 🔎 Metadata Forensics |
| **Challenge ID** | `metadata-forensics-day-10-where-do-we-begin` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day10_quick/m10.py`](../solvers/day10_quick/m10.py) |

## Prompt
> Architecture tells you whether a binary can run; its entry point tells you where execution begins. Map the start addresses and catch the report that is lying.

## TL;DR
One field in every mode: `pe.address_of_entry_point_rva_hex`, the `AddressOfEntryPoint` RVA from the PE optional
header. The only trap was the format. Unpadded `0x65bd0` was graded `incorrect`; the answer must be zero-padded to
8 hex digits, `0x%08x` → `0x00065bd0`. This was the first day of the scheduled run with three lane agents in parallel
(this lane's agent handled warmups, metadata and mobile).

## Artifact
- Days 10–14 break from the Day 8–9 pattern: **every mode asks only the new field**, with no compounding block. The
  answer id is `d09-pe-NNN-pe-address-of-entry-point-rva-hex`. The id reuses the `d09-pe` prefix because the target
  is the same `telemetry-agent-NNN.exe` family introduced on [Day 9](../day09/metadata-built-different.md).
- The target is a Go-built i386 PE inside `metadata-day-10-evidence.zip`. Mastery has 2 sets as nested
  `metadata-day-10-evidence-0K.zip`.

## Solution
```python
e = struct.unpack("<I", b[0x3C:0x40])[0]          # e_lfanew
assert b[e:e + 4] == b"PE\0\0"
o = e + 24                                        # optional header
magic = struct.unpack("<H", b[o:o + 2])[0]        # 0x10b PE32 / 0x20b PE32+
aep = struct.unpack("<I", b[o + 16:o + 20])[0]    # AddressOfEntryPoint (RVA)
answer = "0x%08x" % aep
```
`AddressOfEntryPoint` sits at offset 16 of the optional header in both PE32 and PE32+. It is an RVA, not a virtual
address, so do not add `ImageBase`. The width rule is the same as Day 9's `pe.coff_machine_u16_hex`: pad to the size
of the field (u32 → 8 digits).

`m10.py` also carries extractors for fields that seemed likely to come next (image base, optional-header magic,
entry section name, entry VA, ELF and Mach-O entry points), so a follow-up day would cost one dispatch line. None of
them was asked.

## Time Trial & Mastery
- The timed modes had real timers (about 8 s) and `unique_attempts_remaining` was 1 after the first start, so a
  wasted attempt was costly. The solver does start/retry → fetch → compute → submit in one process (`m10.py <id> retry --submit`),
  about 1–1.5 s end to end. Both modes were CORRECT on the first try.
- The format had already been settled on the untimed single (`0x65bd0` incorrect, `0x00065bd0` CORRECT). That is the
  reason to probe formats on Single Solve before touching a timed mode.

## Lessons / gotchas
- Hex fields in this lane are zero-padded to the field width: `_u16_hex` → 4 digits, RVAs → 8, a 64-bit image base → 16.
- The prompt's "report that is lying" never became a question.
- From [Day 15](../day15/metadata-a-word-to-the-wise.md) on, this field returns in every compounding attempt as
  `d09-pe-001-pe-address-of-entry-point-rva-hex`.
