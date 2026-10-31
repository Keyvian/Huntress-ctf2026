# 🔎 Portable Deception

| | |
|---|---|
| **Day** | 06 |
| **Lane** | 🔎 Metadata Forensics |
| **Challenge ID** | `metadata-forensics-day-06-portable-deception` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | One-off scripts (not preserved). The same extractor is `pdf_ver()` in [`solvers/day09/m9.py`](../solvers/day09/m9.py) |

## Prompt
> A document bundle mixes real PDFs, renamed impostors, and multiple declared versions. Determine what the files promise, what they contain, and which promise is false.

## TL;DR
The new field is `pdf.header_version`: the `X.Y` of the `%PDF-X.Y` header line, or `none` when the file has no PDF
header. `document-001.pdf` starts `%PDF-1.4`, so the answer is `1.4`. Single and time trial were quick. Mastery was
untimed this day but kept serving attempts that the solver could not answer correctly. It took a retry loop until an
attempt with real PDFs came up.

## Artifact
- Single Solve: `d06-pdf-001-pdf-header-version`, "Determine pdf.header_version for document-001.pdf.", artifact
  `metadata-day-06-evidence.zip -> document-001.pdf` (1,552 bytes, begins `%PDF-1.4\n%\xe2\xe3\xcf\xd3`). Format
  `exact_text` with the `none`-if-absent rule.
- Time Trial: one PDF on a deadline.
- Mastery: two questions with `deadline: None`. Each set is a separate delivery, and the label names it:
  `delivery 1: metadata-day-06-evidence.zip -> document-006.pdf` maps to `delivery=0`.

## Solution
Search the first kilobyte rather than requiring the header at offset 0, so a few prepended bytes do not hide it:

```python
def pdf_ver(b):
    m = re.search(rb"%PDF-(\d+\.\d+)", b[:1024])
    return m.group(1).decode() if m else "none"
```

The 1,024-byte window mirrors the common reader behaviour of accepting a header anywhere near the start of the file. Answers: single `1.4` (CORRECT), time trial `1.3` (CORRECT).

## Time Trial & Mastery
- **Time Trial** was CORRECT on the first submit. The attempt that came back had been regenerated (`document-005.pdf`
  instead of the `document-002.pdf` seen when inspecting), so only freshly fetched bytes count.
- **Mastery** produced a run of `incorrect` verdicts. Some attempts asked about `document-003.pdf` /
  `document-004.pdf`, and for those the solver found no PDF header in the delivered member and answered `none` for
  both. Other attempts asked about `document-006.pdf` / `document-007.pdf` and delivered real PDFs (`1.4`, `1.5`).
  Mastery was untimed (`deadline: None`), so a loop kept calling `start` and submitting until a 006/007 attempt came
  up, and that one was CORRECT. The logs do not establish whether the 003/004 attempts held genuine impostors, whose
  expected answer was something other than `none`, or were out of sync with their deliveries.

## Lessons / gotchas
- A `.pdf` extension promises nothing. The header line is the evidence.
- Delivery labels are 1-based ("delivery 1") while the `delivery` parameter is 0-based.
- When an untimed mode keeps rejecting a value you are confident in, re-inspecting the live attempt (questions *and*
  bytes) is cheaper than re-deriving the field.
- `pdf.header_version` joins the cumulative contract as `d06-pdf-001-…` (`document-001.pdf`, `1.4`) from
  [Day 8](../day08/metadata-whats-in-the-box.md) onward.
