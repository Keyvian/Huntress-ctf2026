# 🔎 Page Me Maybe

| | |
|---|---|
| **Day** | 23 |
| **Lane** | 🔎 Metadata Forensics |
| **Challenge ID** | `metadata-forensics-day-23-page-me-maybe` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day23_quick/m23.py`](../solvers/day23_quick/m23.py) + SQLite header parser [`sqlite.py`](../solvers/day23_quick/sqlite.py) |

## Prompt
> Application databases have been copied, truncated, embedded, and mislabeled. Validate page geometry, connect databases to parent applications, and find the impossible claim.

## TL;DR
The new field, `sqlite.page_size_bytes`, is trivial: header bytes 16–17 big-endian, where the value 1 means 65536. The
first full time-trial submit was nevertheless `incorrect`. Bisecting with one-answer partial submits found two
latent bugs. One was a suffix-matching collision in the solver: `…-page-size-bytes` was answered with the *file*
size. The other was a grader convention: two array fields from earlier days are compared **sorted**, and this day's
variants were the first whose inputs were not already in sorted order.

## Artifact
- `database-001.sqlite`, answer id `d23-sqlite-001-sqlite-page-size-bytes`.
- Values seen: 4096 (single), 32768 (time trial), 16384 / 1024 / 65536 / 1024 / 1024 / 16384 / 2048 (mastery sets
  1–7). Every database was a plain file (header at offset 0, header page count × page size = file size). The "copied,
  truncated, embedded, mislabeled" story never became a question.
- Time Trial: **28 questions**. Mastery: **7 sets × 28 = 196**, all seven `evidence-0N.zip` inside the default artifact.

## Solution
```python
assert db[:16] == b"SQLite format 3\x00"
ps = struct.unpack(">H", db[16:18])[0]
page_size = 65536 if ps == 1 else ps      # 65536 does not fit in a u16, so it is stored as 1
```

`sqlite.py` goes further, for the prompt's story:

- Locates an embedded database by searching for the magic, and reports `header_offset`.
- Compares the header page count (bytes 28–31) with `file_size / page_size` to flag truncation and "impossible
  claims".
- Reads text encoding, `application_id` (as an integer and as ASCII), `user_version` and freelist counts.
- Lists schema tables and row counts through the stdlib `sqlite3` module on a read-only temporary copy.

## Time Trial & Mastery
The first full time-trial submit came back `incorrect`. Partial batches are banked (`accepted` + `remaining`), so the
agent submitted one answer per request to find the culprits:

1. **Suffix collision in the solver.** `m15.solve` handles the identity block by answer-id suffix, and any id ending in
   `-size-bytes` received the member's *file size* before the question text was read. `…-sqlite-page-size-bytes`
   therefore came back as 98304 (the file size) instead of 32768. `m23.solve` now re-resolves every
   `Determine sqlite.<field> for …` question after the generic pass.
2. **Grader sorts two old array fields.** `zip.central_directory_member_names` (from
   [Day 8](../day08/metadata-whats-in-the-box.md)) and `macho.cpu_type_set` (from
   [Day 20](../day20/metadata-universal-appeal.md)) are compared as **sorted** arrays: names lexicographically,
   cputypes numerically. Days 8–22 passed with file order only because the inputs happened to be sorted already. This
   day's variants shuffled both: central-directory names like `shelf-08`, `cabinet-03`, …, and fat Mach-O slices
   `arm64_32`, `arm64`, `ppc`. File order was `incorrect`, sorted was CORRECT. `m23.field_value` now sorts both.

After both fixes: Time Trial CORRECT 28/28, Mastery CORRECT 196/196 in a one-shot 3.3 s run. Single had been
submitted by hand (`4096`) and was CORRECT. Answers are strings: a raw integer returns `error: invalid_answers`.

## Lessons / gotchas
- Dispatch on the question text (`Determine <family.field> for …`), not on loose id suffixes. New families can reuse
  words like `size-bytes` with a different meaning.
- A compounding lane re-tests old fields on new random inputs every day. A convention that "passed" for two weeks can
  still be wrong. Bisect with one-answer partial submits instead of guessing.
- If an array's format says "exact values and order" but the order has no meaning (member names, CPU types), expect a
  sorted comparison.
