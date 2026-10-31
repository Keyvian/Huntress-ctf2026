# 🔎 Looks Can Be Deceiving

| | |
|---|---|
| **Day** | 02 |
| **Lane** | 🔎 Metadata Forensics |
| **Challenge ID** | `metadata-forensics-day-02-looks-can-be-deceiving` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/solve_meta2.py`](../solvers/solve_meta2.py) |

## Prompt
> The extensions claim one story; the first sixteen bytes tell another. Identify what each artifact actually is and isolate the deliberate disguise.

## TL;DR
One question per file: "What are the first sixteen bytes as lowercase hexadecimal?" The answer is
`data[:16].hex()` on the decompressed member. The "disguise" is a PDF named `disguised-report.bin`. The real trap was
operational. The mastery timer is only a few seconds, and a gather loop that made 11 requests crossed the deadline.
The attempt then regenerated, and the solver answered old questions with new files.

## Artifact
| Mode | Answer id | Target |
|---|---|---|
| Single Solve | `evidence-note-magic-prefix-hex-16` | `metadata-day-02-evidence.zip -> evidence-note.txt` (starts `Huntress Metadat…`) |
| Time Trial | `roster-magic-prefix-hex-16` | `roster.csv` (starts `analyst_id,case_…`) |
| Mastery set 1 | `set1.evidence-note-copy-magic-prefix-hex-16` | `metadata-day-02-evidence-01.zip -> evidence-note-copy.txt` |
| Mastery set 2 | `set2.disguised-report-magic-prefix-hex-16` | `metadata-day-02-evidence-02.zip -> disguised-report.bin`, actually `%PDF-1.7` |

Format: `pattern`, "exact 32 hexadecimal characters representing the first 16 bytes; use no 0x prefix or spaces".
The mastery default artifact is an outer ZIP containing the two per-set ZIPs.

## Solution
`solve_meta2.py` generalizes the [Day 1](../day01/metadata-you-must-be-this-hash-to-ride.md) solver into "compute the
property the question asks for" on the resolved member:

```python
if "hex" in low:
    m = re.search(r"hex-(\d+)", qid)        # N comes from the "...-hex-<N>" suffix
    n = int(m.group(1)) if m else 16
    return data[-n:].hex() if "last" in low else data[:n].hex()
```

- Parse `N` from the `hex-<N>` suffix of the answer id. An earlier version took the first number in the id, which on
  mastery is the `1` of `set1.` and produced 1-byte answers.
- Never trust the extension. `disguised-report.bin` begins `25 50 44 46 2d 31 2e 37` (`%PDF-1.7`), and that is what
  the grader expects.

## Time Trial & Mastery
- Single Solve and Time Trial were CORRECT on the first submit.
- Mastery failed twice with `incorrect`, and both failures looked alike. The gathered files were
  `mutation-baseline.dat` and `one-byte-off.dat`, two decoys that both begin `HUNTRESS-MUTATIO…`, while the questions
  still named `evidence-note-copy.txt` and `disguised-report.bin`. The gather fetched the default artifact plus
  `delivery=0..9`, 11 requests in total. That crossed the short mastery deadline, the attempt expired and regenerated,
  and the later fetches returned another attempt's packaging.
- Fix: fetch the default artifact once, since it already bundles every set as nested ZIPs, and probe delivery indices
  only when sets are missing. With one request the attempt stayed consistent, and the submit was CORRECT.

## Lessons / gotchas
- On a timed attempt every request counts. Start, fetch, compute and submit in one process with as few calls as
  possible.
- Symptom of a desync: the questions reference members that are not in what you gathered. Check that before submitting
  (the [Day 3](../day03/metadata-bom-voyage.md) solver turns this into an explicit consistency gate).
- "First N bytes as lowercase hex" stays in the compounding contract to the end of the event as
  `evidence-note-magic-prefix-hex-16`.
