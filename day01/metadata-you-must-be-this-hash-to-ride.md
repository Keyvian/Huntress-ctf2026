# 🔎 You Must Be This Hash to Ride

| | |
|---|---|
| **Day** | 01 |
| **Lane** | 🔎 Metadata Forensics |
| **Challenge ID** | `metadata-forensics-day-01-hash-to-ride` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/solve_meta.py`](../solvers/solve_meta.py) |

## Prompt
> Three ordinary files arrived without trustworthy labels. Build an identity inventory from the bytes themselves and prove which labels can—and cannot—be trusted.

## TL;DR
The lane opener is a file-identity inventory: exact filename, size in bytes, MD5, SHA-1 and SHA-256 of one file
inside a ZIP. The only real difficulty was packaging. Mastery ships an outer ZIP that holds one inner ZIP per set, and
two sets can contain files with the same size and similar names. Hash the decompressed member that sits inside the
inner ZIP the question names, and nothing else.

## Artifact
Every mode asks five questions about one target file. The three files that rotate between modes are the "three
ordinary files" of the prompt:

| Mode | Archive | Target | Answer ids |
|---|---|---|---|
| Single Solve | `metadata-day-01-evidence.zip` | `evidence-note.txt` | `evidence-note-{filename,size-bytes,md5,sha1,sha256}` |
| Time Trial | `metadata-day-01-evidence.zip` | `roster.csv` (CSV header `case_marker,endpoint_id,analyst_id,collected_sequence,status`) | `roster-*` |
| Mastery | outer ZIP → `metadata-day-01-evidence-01.zip`, `-02.zip` | set 1: `evidence-note-copy.txt` ("the renamed evidence-note copy"), set 2: `evidence-note.txt` | `set1.evidence-note-copy-*`, `set2.evidence-note-*` |

Answer formats, quoted from the `answer_format` objects:

- `*-filename`: `exact_text`, "exact base filename including its extension, with no directory path, quotes, or
  explanatory text". The question is "What is the exact filename of the first evidence note?" Its `artifact` field
  is only the ZIP name, with no `-> member` part, so the name has to come from the archive listing.
- `*-size-bytes`: `integer`, "base-10 integer with no units, separators, or explanatory text".
- `*-md5` / `*-sha1` / `*-sha256`: `pattern`, 32/40/64 hex characters, case-insensitive.

The other questions in each group carry `artifact: "<zip> -> <member>"`. That string is the most reliable hint for
which member to read.

## Solution
1. `POST {"op":"start", ...}`. A bare `{"challenge": ...}` body only returns the contract (questions with null
   `answer_ids`), and the artifact call then answers `{"error":"start_required"}`.
2. Fetch the default artifact and recursively flatten it. Inner ZIPs are expanded and every leaf keeps its full path
   (`metadata-day-01-evidence-02.zip -> evidence-note.txt`), so identical basenames from different sets stay distinct.
3. Group the questions by prefix (`set2.evidence-note`), parse the member hint after `->`, and resolve it to a leaf:
   exact basename first, preferring the leaf inside the inner ZIP named on the left of `->`. If that fails, fall back
   to content: evidence notes carry a recognizable template header (`Metadata Forensics`, `Case marker`, `Analyst`,
   `Endpoint`), and the roster is the CSV that starts with `case_marker`.
4. Compute everything on the decompressed bytes:

```python
def digests(b):
    return {"size-bytes": str(len(b)),
            "md5": hashlib.md5(b).hexdigest(),
            "sha1": hashlib.sha1(b).hexdigest(),
            "sha256": hashlib.sha256(b).hexdigest()}
```

5. The filename answer is the resolved member's basename. Every answer is submitted as a string.

## Time Trial & Mastery
- **Time Trial** (`roster.csv`) was solved in one process: start, fetch, hash, submit. The hashes differed from an
  earlier inspection of the same mode because `retry` regenerates the content. Only freshly fetched bytes are valid.
- **Mastery** was locked (`{"error":"prerequisite_required"}`) until the time trial was solved. Its first submit was
  `incorrect`. The solver had flattened the two inner ZIPs by basename and resolved set 2 to set 1's
  `evidence-note-copy.txt`. Both files were 240 bytes, so the size alone did not reveal the mix-up. Keeping the
  container in the path and matching the inner-ZIP name fixed it, and the next run was CORRECT.
- The final solver gathers in one process: the default artifact first, then delivery indices only if sets are missing.
  The deliveries are 0-based, so "delivery 1" in a label means `delivery=0`.

## Lessons / gotchas
- Labels in this lane are deliberately untrustworthy. A "copy" can carry another file's name, and identical sizes
  prove nothing. Identity comes from the digest of the real bytes.
- Hash the decompressed member, never the stored (compressed) bytes or the outer archive.
- Keep the nested path (`outer.zip -> inner.zip -> member`) through the whole pipeline. Every later day reuses this
  layout: one inner ZIP per mastery set.
- These questions become the "identity block" that the lane keeps compounding. [Day 8](../day08/metadata-whats-in-the-box.md)
  and [Day 9](../day09/metadata-built-different.md) open with the `evidence-note` block. From
  [Day 15](../day15/metadata-a-word-to-the-wise.md) on, every timed attempt mixes `roster`, `evidence-note` and
  `evidence-note-copy` questions of exactly this kind.
