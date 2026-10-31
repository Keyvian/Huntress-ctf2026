# 🔎 Event Horizon

| | |
|---|---|
| **Day** | 24 |
| **Lane** | 🔎 Metadata Forensics |
| **Challenge ID** | `metadata-forensics-day-24-event-horizon` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day24_quick/m24.py`](../solvers/day24_quick/m24.py) + EVTX parser [`evtx.py`](../solvers/day24_quick/evtx.py) (dump tool: [`evtx_dump.py`](../solvers/day24_quick/evtx_dump.py)) |

## Prompt
> Windows event logs from several hosts have been duplicated, truncated, and bundled with reports. Count records accurately and find the selectively shortened timeline.

## TL;DR
The new field is `evtx.record_count` for `events-001.evtx`: the number of complete, well-formed event records actually
present in the file, found by walking every chunk record by record rather than trusting the header's counters. In
every variant the walk agreed with both header claims. The day's real catch was a latent bug in the identity block:
two of the 232 mastery filename answers would have been wrong. It was caught offline before the submit.

## Artifact
- `events-001.evtx` (`ElfFile` magic), answer id `d24-evtx-001-evtx-record-count`.
- All 10 variants seen (single 3 records, time trial 75, mastery 33 / 37 / 66 / 73 / 5 / 89 / 60 / 95) were 4096 +
  1 × 65536 bytes: one chunk, all CRCs valid, and walked count = header-claimed count = chunk-claimed count. The
  "duplicated, truncated, selectively shortened" story never became a question or a trap.
- Time Trial: **29 questions**. Mastery: **8 sets × 29 = 232**.

## Solution
EVTX layout: a 4,096-byte file header (`ElfFile\0`, oldest/current chunk numbers, `next_record_id`, chunk count,
flags, CRC-32 of the first 120 bytes), then 64 KiB chunks (`ElfChnk\0`, first/last record number, free-space offset,
header and record CRC-32s). Each record is `**\0\0`, size (u32), record id (u64), FILETIME, the BinXML body, then the
size repeated as a trailer.

```python
recs, off = [], 4096
while off < len(b):
    c = b[off:off + 65536]
    if c[:8] == b"ElfChnk\0":
        p = 512                                   # records start after the 512-byte chunk header
        while p + 28 <= len(c) and c[p:p + 4] == b"**\0\0":
            sz = struct.unpack_from("<I", c, p + 4)[0]
            if sz < 28 or p + sz > len(c): break                       # partial record
            if struct.unpack_from("<I", c, p + sz - 4)[0] != sz: break  # trailer mismatch
            recs.append(struct.unpack_from("<Q", c, p + 8)[0])          # record id
            p += sz
    off += 65536
answer = str(len(recs))
```

`evtx.py` also computes the claimed counts (`next_record_id − 1` and Σ(last − first + 1) over chunks),
unique and duplicate record ids, truncated and partial flags, the first and last ids and UTC times, and prints an
`EVTX … WALKED n` line per file. A truncated or duplicated variant would have shown up before the submit.

## Time Trial & Mastery
- Single CORRECT (3). Time Trial CORRECT 29/29 one-shot. Mastery CORRECT 232/232 in 2.5 s end to end.
- **Latent identity-block bug, found offline on the cached mastery before submitting.** The `*-filename` questions
  ("What is the exact filename of the roster / first evidence note?") have no member in their artifact field. `m15`
  inferred them from sibling questions, which failed twice:
  - `set6.roster-filename` had **no** sibling roster question, so the answer was `UNKNOWN`.
  - `set5.evidence-note-filename` picked `evidence-note-copy-be89c1.txt` (the first matching sibling) instead of
    `evidence-note-1a9a73.txt`.

  Member names by now carried random 6-hex tags. `m24.solve` resolves filename questions from the container's member
  list with `^<stem>(-[0-9a-f]{6})?\.\w+$`. A unique match is authoritative, and the 6-hex tag keeps `evidence-note`
  from matching `evidence-note-copy-…`. The fix was verified offline (`m24.py x none --dir <saved>`) on both the
  time-trial and mastery caches before the single mastery submit.

## Lessons / gotchas
- Count what is present, not what the header claims. In EVTX the header's `next_record_id`, the chunk ranges and the
  real records can all disagree after tampering. Print all three.
- Questions that look trivial still need structural resolution. "The roster" means the member whose name stem is
  `roster`, not whatever a neighbouring question points to.
- Saving every timed attempt (`--save`) and re-running offline (`--dir`) catches bugs before they cost a submit.
