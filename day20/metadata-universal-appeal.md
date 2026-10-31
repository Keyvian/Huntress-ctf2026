# 🔎 Universal Appeal

| | |
|---|---|
| **Day** | 20 |
| **Lane** | 🔎 Metadata Forensics |
| **Challenge ID** | `metadata-forensics-day-20-universal-appeal` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day20_quick/m20.py`](../solvers/day20_quick/m20.py) + Mach-O parser [`macho.py`](../solvers/day20_quick/macho.py) (format probe: [`probe20.py`](../solvers/day20_quick/probe20.py)) |

## Prompt
> A macOS deployment includes thin and universal binaries mixed with archives. Enumerate every CPU type and identify what truly supports the advertised fleet.

## TL;DR
The new field is `macho.cpu_type_set` for `macos-001.bin`, a `json` answer: "compact JSON array with exact values and
order". The open question was the vocabulary. The untimed single was used to probe it: `["arm64"]` and `["ARM64"]` were
`incorrect`, and the raw `cputype` as zero-padded 8-digit hex, `["0x0100000c"]`, was CORRECT.

## Artifact
- `macos-001.bin`: 56 bytes, an `MH_MAGIC_64` little-endian header with `cputype 0x0100000c` (`CPU_TYPE_ARM64` =
  `CPU_ARCH_ABI64 | 12`), `cpusubtype 0`, `MH_EXECUTE`, and one load command (`LC_UUID`).
- Answer id `d20-macho-001-macho-cpu-type-set`.
- Time Trial: **25 questions**. Mastery: **5 sets × 25 = 125**. Every variant seen on this day was the same thin arm64
  header. The synthesis question now includes `macos-001.bin`.

## Solution
```python
MAGIC = {b"\xfe\xed\xfa\xce": ">", b"\xce\xfa\xed\xfe": "<",
         b"\xfe\xed\xfa\xcf": ">", b"\xcf\xfa\xed\xfe": "<"}
if b[:4] in MAGIC:                                   # thin Mach-O
    ct, cst = struct.unpack(MAGIC[b[:4]] + "iI", b[4:12])
    types = [ct & 0xffffffff]
elif b[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):   # FAT / FAT_64, always big-endian
    n = struct.unpack(">I", b[4:8])[0]
    types = [struct.unpack(">i", b[8 + 20*i:12 + 20*i])[0] & 0xffffffff for i in range(n)]
answer = json.dumps(["0x%08x" % t for t in sorted(set(types))], separators=(",", ":"))
```

`macho.py` handles:

- Thin `MH_MAGIC` / `MH_MAGIC_64` in both byte orders.
- `FAT_MAGIC` / `FAT_MAGIC_64` (big-endian `fat_arch` lists). Java class files share the `CAFEBABE` magic and are
  rejected with an `nfat_arch` sanity check.
- `!<arch>` static libraries (member cputypes, BSD `#1/NN` long names, `__.SYMDEF` skipped) and nested ZIPs.

`cpu_types()` returns the deduplicated (cputype, cpusubtype) pairs. `name()` renders them in several styles (`lipo`,
upper, constant, `hex8`, …). `probe20.py <id> <answer_id> <candidate>...` submits one-answer candidates on an untimed
attempt, which is how the vocabulary was settled.

## Time Trial & Mastery
Regular untimed attempts. Time Trial CORRECT 25/25, Mastery CORRECT 125/125.

The array order was first emitted in **file order** (the `fat_arch` order). [Day 23](../day23/metadata-page-me-maybe.md)
served fat variants with shuffled slices (`arm64_32`, `arm64`, `ppc`) and found that the grader expects the cputypes
**sorted numerically**. The excerpt above already includes that fix.

## Lessons / gotchas
- When the answer vocabulary is undocumented, probe it on the untimed single with one-answer submits. A wrong
  candidate costs nothing there.
- "Exact values and order" did not mean file order, here or for `zip.central_directory_member_names`. Sort sets that
  have no meaningful order.
- `0x0100000c`: the high byte `0x01` is the `CPU_ARCH_ABI64` flag, the low part `12` is ARM. arm64e would differ only
  in `cpusubtype`, which this field does not report.
