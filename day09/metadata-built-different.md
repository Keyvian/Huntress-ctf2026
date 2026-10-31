# 🔎 Built Different

| | |
|---|---|
| **Day** | 09 |
| **Lane** | 🔎 Metadata Forensics |
| **Challenge ID** | `metadata-forensics-day-09-built-different` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day09/m9.py`](../solvers/day09/m9.py) |

## Prompt
> A software drop contains executables for several architectures, plus decoys wearing executable extensions. Determine what can actually run where.

## TL;DR
The Day-8 contract plus one PE field: `pe.coff_machine_u16_hex`, the COFF `Machine` field of
`telemetry-agent-001.exe`, written as `0x%04x` (`0x014c` = i386). On the untimed single, the 12 known answers were
banked first as a subset, then the new field went alone, so a format mistake could not cost the rest. Time Trial
and Mastery were then one-shot. Day 9 was the first day the scheduled headless agent solved entirely on its own, from
WSL.

## Artifact
`metadata-day-09-evidence.zip` (598,758 bytes):

| Member | Size | Note |
|---|---|---|
| `evidence-note.txt` | 33 | `Case <hex> evidence note.` |
| `camera-001.jpg` | 3,025 | JPEG 257×146 |
| `panel-001.png` | 414 | PNG 269×153 |
| `document-001.pdf` | 1,552 | PDF 1.4 |
| `evidence-drop-001.zip` | 410 | 2 stored entries |
| `telemetry-agent-001.exe` | 1,257,984 | PE32 console, Intel i386, 7 sections |

13 answer ids: the 12 from [Day 8](../day08/metadata-whats-in-the-box.md) plus `d09-pe-001-pe-coff-machine-u16-hex`
("Determine pe.coff_machine_u16_hex for telemetry-agent-001.exe."). In the timed modes every question text carries an
`[assigned-artifact-sha256:<sha256>]` suffix that pins the expected bytes. Mastery: 5 sets × 13 = 65 questions over
`metadata-day-09-evidence-01.zip` … `-05.zip`.

## Solution
The questions follow two shapes. The identity block ("What is its MD5 digest?") is resolved from the answer-id suffix
(`-size-bytes`, `-md5`, `-sha1`, `-sha256`, `-magic-prefix-hex-N`). Everything else reads
`Determine <family.field> for <file>.`, and `m9.py` routes the field name through a dispatch table:

```python
FIELDS = {
    "text.utf8_bom_present": text_bom,
    "jpeg.sof_dimensions_pixels": jpeg_sof,
    "png.ihdr_dimensions_pixels": png_ihdr,
    "pdf.header_version": pdf_ver,
    "zip.eocd_total_entries": zip_eocd_total,
    "zip.central_directory_member_names": zip_cd_names,
    "pe.coff_machine_u16_hex": lambda b: "0x%04x" % pe_hdr(b)["machine"],
}
```

PE header: `e_lfanew` at `0x3C` points to `PE\0\0`, followed by the COFF header, whose first field is
`Machine` (u16 LE). `0x014c` is `IMAGE_FILE_MACHINE_I386`; `0x8664` would be AMD64 and `0xaa64` ARM64. The answer is
the raw field as lowercase hex padded to the field width, 4 digits for a u16.

Single Solve was submitted in two batches: the 12 already-known answers (`accepted`, `remaining: 1`), then the PE
field alone, which returned CORRECT. The first guess `0x014c` was right.

## Time Trial & Mastery
- Time Trial: 13/13 CORRECT on the first submit.
- Mastery: all five nested ZIPs contain members with the same basenames (`camera-001.jpg` in every set).
  `find_member()` was extended to disambiguate with the container named on the left of `->`
  (`metadata-day-09-evidence-03.zip`), falling back to the set number. 65/65 CORRECT on the first submit.
- Every set seen answered `0x014c` (i386). The "several architectures" and "decoys wearing executable extensions"
  never became questions.

## Lessons / gotchas
- The `_u16_hex` suffix is the format spec: zero-padded to the field width. The same convention returns as
  `0x%08x` for RVAs ([Day 10](../day10/metadata-where-do-we-begin.md)) and `0x%04x` for ELF `e_machine`
  ([Day 19](../day19/metadata-little-endian-on-the-prairie.md)).
- On an untimed mode, bank the confident answers first and probe new fields one at a time. A batch with one wrong answer
  banks nothing.
- `m9.py` is the ancestor of every later metadata solver: each day's `mNN.py` wraps the previous one and adds one
  family to the dispatch.
