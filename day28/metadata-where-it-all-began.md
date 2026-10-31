# 🔎 Where It All Began

| | |
|---|---|
| **Day** | 28 |
| **Lane** | 🔎 Metadata Forensics |
| **Challenge ID** | `metadata-forensics-day-28-where-it-all-began` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day28_quick/m28.py`](../solvers/day28_quick/m28.py) + raw disk parser [`disk.py`](../solvers/day28_quick/disk.py) |

## Prompt
> Disk images hold every previous artifact family in context. Recover partition layouts, locate evidence by offset, and prove which image was rebuilt from an incomplete source.

## TL;DR
The new field is `disk.partition_start_lba_sequence` for `disk-001.img`: a compact JSON array of the starting LBA of
each partition. Every image served was GPT with 512-byte sectors, so the work is reading the GPT header at LBA 1 and its
partition-entry array. Variant 000 has one partition starting at LBA 34, so the answer is `[34]`.

## Artifact
- Variant 000: a 128 KiB image. A protective MBR (type `0xEE`, start LBA 1), the primary GPT at LBA 1, the backup at the
  last LBA, 128 entries × 128 bytes, and one partition named `HUNTRESS EVIDENCE` (basic-data type GUID) at LBA
  34–222. Answer `[34]`.
- The other 13 images seen (time trial and mastery) were all GPT, 512-byte sectors, with valid primary and backup
  header/entry CRCs. Each had 1–6 partitions with entries contiguous from index 0 and **already in ascending start
  order**, so table order equals sorted order and there was no ordering ambiguity. Type GUIDs were basic-data, Linux,
  ESP, swap or recovery; names looked like `data2` or `boot9`.
- No MBR-only or damaged-primary image appeared. "Locate evidence by offset / rebuilt from an incomplete source" never
  became a question.
- Answer id `d28-disk-001-disk-partition-start-lba-sequence`. Time Trial: **33 questions**. Mastery:
  **12 sets × 33 = 396**.

## Solution
```python
ss = 512
assert b[ss:ss + 8] == b"EFI PART"                       # GPT header at LBA 1
hdr = b[ss:ss + 92]
entries_lba, n_entries, entry_size = struct.unpack_from("<QII", hdr, 72)
starts = []
for i in range(n_entries):
    e = b[entries_lba * ss + i * entry_size:][:entry_size]
    if e[:16] == b"\0" * 16:                             # unused entry (type GUID all zero)
        continue
    first_lba = struct.unpack_from("<Q", e, 32)[0]       # entry: type GUID, unique GUID, first LBA, last LBA, attrs, name
    starts.append(first_lba)
answer = json.dumps(starts, separators=(",", ":"))       # "[34]"
```

The GPT header records where the entry array lives (`PartitionEntryLBA` at offset 72), how many entries there are,
and their size. Each 128-byte entry is type GUID (16), unique GUID (16), **first LBA (8)**, last LBA (8), attributes
(8), and a UTF-16LE name (72).

`disk.py` also handles plain MBR partition tables with extended-partition (EBR) chains, falls back to the backup GPT
when the primary is invalid, validates the header and entry-array CRC-32s, detects 4096-byte sectors (`EFI PART` at
4096), and prints any problem in its `DISK` line.

## Time Trial & Mastery
Regular untimed attempts. Single CORRECT, Time Trial CORRECT 33/33 one-shot, Mastery CORRECT 396/396.

## Lessons / gotchas
- Ignore the protective MBR when a GPT is present: its single `0xEE` entry (start 1) describes the GPT itself, not a
  partition.
- Every image served had its entries already in start order. If table order and sorted order ever differ, that is
  the case to probe on the untimed single, because the
  [Day 23](../day23/metadata-page-me-maybe.md) lesson says arrays may be compared sorted.
