# 🔎 Seven-Zip, No Relation

| | |
|---|---|
| **Day** | 07 |
| **Lane** | 🔎 Metadata Forensics |
| **Challenge ID** | `metadata-forensics-day-07-seven-zip-no-relation` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | One-off scripts (not preserved). The same extractor is `zip_eocd_total()` in [`solvers/day09/m9.py`](../solvers/day09/m9.py) |

## Prompt
> Files arrive inside and beside a collection of ZIP archives. Count what the archives claim, distinguish empty space from evidence, and find the census that does not add up.

## TL;DR
The new field is `zip.eocd_total_entries`: the "total number of entries in the central directory" stored in a ZIP's
End Of Central Directory record. It is a 2-byte little-endian value at offset +10 from the `PK\x05\x06` signature.
The target is a ZIP inside the evidence ZIP, and in mastery a ZIP inside a ZIP inside a ZIP. This mastery is where the
team found `op=practice` and learned that answers must be JSON strings.

## Artifact
- Single Solve: `d07-zip-001-zip-eocd-total-entries`, "Determine zip.eocd_total_entries for
  evidence-drop-001.zip.", artifact `metadata-day-07-evidence.zip -> evidence-drop-001.zip` (410 bytes). Format
  `integer`, "base-10 integer with no units, separators, or explanatory text".
- Mastery: `set1.d07-zip-006-zip-eocd-total-entries` and `set2.d07-zip-007-…`. The default artifact nests twice:
  outer ZIP → `metadata-day-07-evidence-0K.zip` → `evidence-drop-00N.zip`. Some levels may be WinZip-AES with the
  event password `infected`, so the solver opens every level with `pyzipper` and falls back to `zipfile`.

## Solution
```python
def eocd_total(b):
    i = b.rfind(b"PK\x05\x06")                 # last EOCD signature
    return struct.unpack("<H", b[i + 10:i + 12])[0] if i >= 0 else None
```
EOCD layout: signature (4), disk number (2), CD start disk (2), entries on this disk (2), **total entries (2)**,
CD size (4), CD offset (4), comment length (2). Searching from the end avoids false hits in member data. Recurse
through every nested ZIP and key the leaves by basename to find `evidence-drop-00N.zip`, then read its EOCD. The
inner archive is never extracted; the question is about what the archive *claims*.

For reference, `evidence-drop-001.zip` has 2 entries (`room-01/item-1.txt`, `room-02/item-1.txt`), the value the
cumulative contract keeps asking from [Day 8](../day08/metadata-whats-in-the-box.md) on.

## Time Trial & Mastery
- Single Solve and Time Trial were solved by an earlier run on the same identity. Its notes were not kept beyond the
  verdicts.
- **Mastery** looked blocked. `start` returned an expired attempt with `unique_attempts_remaining: 0`, and `retry`
  returned `{"error":"rotation_exhausted"}`. The answers were already computed (set 1 = `2`, set 2 = `3`), but there
  was no live attempt to take them.
- Two discoveries unblocked it:
  1. The GM's `op=openapi` document describes the POST operation as "Start or resume an attempt, submit answers,
     retry with a new variant, **or continue unranked after exhaustion**". Its `op` enum is
     `start | submit | retry | practice`. `op=practice` returned a live attempt with `deadline: null`: untimed,
     unranked and repeatable.
  2. The same schema types `answers` as an object of **string → string**. The earlier submit of Python integers had
     returned `{"error":"invalid_answers"}`. Sent as `"2"` and `"3"`, the practice attempt was CORRECT in 1.5 s.
- Collecting the double-nested members also took two fixes. `delivery=1` was invalid because both sets live in the
  default artifact, and a one-level unzip found no `evidence-drop-*.zip`, so the walk had to be recursive.

## Lessons / gotchas
- Always `str()` every answer, integers included.
- `op=practice` means no mode is ever permanently blocked. It became the standard escape hatch for exhausted or
  infeasible ranked modes for the rest of the event.
- Recurse into nested archives whatever the extension, and expect AES-encrypted levels (`infected`).
- The prompt's "census that does not add up" (EOCD count versus actual entries) never became its own question.
  [Day 8](../day08/metadata-whats-in-the-box.md) adds the central-directory *names*.
