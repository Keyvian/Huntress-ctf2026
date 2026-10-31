# 🔎 BOM Voyage

| | |
|---|---|
| **Day** | 03 |
| **Lane** | 🔎 Metadata Forensics |
| **Challenge ID** | `metadata-forensics-day-03-bom-voyage` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/solve_meta2.py`](../solvers/solve_meta2.py) |

## Prompt
> A text export pipeline produced files that look identical in an editor but behave differently in scripts. Find the encoding landmines before they break the investigation.

## TL;DR
The new field is `text.utf8_bom_present`, an enum `true` / `false`: does the file start with `EF BB BF`? Reading
three bytes is the whole computation. The time trial still cost several attempts. Some timed attempts were
inconsistent: the delivered archive did not contain the file the question asked about. Detecting that and rolling a
fresh attempt is what solved it.

## Artifact
| Mode | Answer id | Target |
|---|---|---|
| Single Solve | `evidence-note-text-utf8-bom-present` | `metadata-day-03-evidence.zip -> evidence-note.txt` |
| Time Trial | `roster-text-utf8-bom-present` | `roster.csv` (29 bytes, `host,case\n…`) |
| Mastery set 1 | `set1.evidence-note-copy-text-utf8-bom-present` | `…-evidence-01.zip -> evidence-note-copy.txt` |
| Mastery set 2 | `set2.d03-text-001-text-utf8-bom-present` | `…-evidence-02.zip -> export-001-with-bom.txt` |

The question reads "Determine text.utf8_bom_present for evidence-note.txt." with
`answer_format: {"kind": "enum", "accepted_values": ["true", "false"]}`. This is the first appearance of the
`Determine <family>.<field> for <file>.` wording and of the `dNN-<type>-NNN-<field>` id scheme. The whole lane uses
both from here on. The decoy filenames (`export-00N-with-bom.txt`, `export-00N-clean.txt`) describe the content and
cannot be trusted. Only the bytes count.

## Solution
```python
u8 = data[:3] == b"\xef\xbb\xbf"
answer = "true" if u8 else "false"
```
`solve_meta2.py` also answers UTF-16 BOM and line-ending variants (`FF FE` / `FE FF`, CRLF), but no question used them.
The single solve (`evidence-note.txt`, no BOM → `false`) was CORRECT on the first submit.

## Time Trial & Mastery
- The first time-trial submit was `incorrect`. The question asked about `roster.csv`, but the attempt had delivered
  `export-002-clean.txt`.
- A fresh, consistent attempt delivered `roster.csv` (no BOM, `false`) as expected.
- Behaviour behind the failure: `start` and `retry` *resume* a still-valid attempt, bad ones included, with the same
  deadline. The inconsistent attempt had to expire (about 15 s) before a new `start` produced a fresh one.
- The solver gained a consistency gate. It submits only when every basename the questions ask about is among the
  gathered files, and otherwise exits so a wrapper loop can retry in a new process:

```python
hints = [parse_art(q.get("artifact"))[1] for q in qs]
consistent = all(h is None or any(base(p) == h for p in files) for h in hints)
if timed and not consistent:
    sys.exit(3)   # skip; let the attempt expire and start again
```

- Mastery (2 sets, nested `-01.zip` / `-02.zip`) unlocked after the time trial and was CORRECT with the same solver.

## Lessons / gotchas
- Filenames that announce their own content (`-with-bom`, `-clean`) are a lure. Read the first three bytes.
- An incorrect verdict on a trivially computable field almost always means a desync: the questions and the files belong
  to different attempts. Gate on consistency instead of debugging the field.
- The BOM question joins the cumulative contract as `evidence-note-text-utf8-bom-present` and is asked in every later
  compounding attempt.
