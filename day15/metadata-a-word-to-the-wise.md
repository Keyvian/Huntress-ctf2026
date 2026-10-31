# 🔎 A Word to the Wise

| | |
|---|---|
| **Day** | 15 |
| **Lane** | 🔎 Metadata Forensics |
| **Challenge ID** | `metadata-forensics-day-15-word-to-the-wise` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day15_quick/m15.py`](../solvers/day15_quick/m15.py) + OOXML parser [`ooxml.py`](../solvers/day15_quick/ooxml.py) |

## Prompt
> Office documents contain relationships that point beyond the page. Separate internal references from external dependencies and find the document reaching somewhere it should not.

## TL;DR
Two things happened this day. The new field is `ooxml.external_relationship_targets`: every relationship with
`TargetMode="External"` across a `.docx`'s `.rels` parts, answered as a **sorted** compact JSON array (document order
was graded `incorrect`). The timed modes also went back to the compounding contract, this time for good: 20 questions
covering every metadata family since Day 1, plus a new "synthesis" question that orders files by SHA-256. `m15.py`
re-merges all the old extractors into one solver, which every later day extends.

## Artifact
- Single Solve: one question, `d15-ooxml-001-ooxml-external-relationship-targets`, "Determine
  ooxml.external_relationship_targets for document-15-001.docx.", artifact
  `metadata-day-15-evidence.zip -> document-15-001.docx`. Format `json`: "compact valid JSON array with exact values
  and order".
- Time Trial: **20 questions** on one evidence bundle (`roster.csv`, `evidence-note.txt`, `evidence-note-copy.txt`,
  `camera-001.jpg`, `panel-001.png`, `document-001.pdf`, `evidence-drop-001.zip`, `telemetry-agent-001.exe`,
  `managed-001.dll`, `installer-001.msi`, `shortcut-001.lnk`, `document-15-001.docx`):

| Group | Answer ids (time-trial instance) |
|---|---|
| Identity sample (5) | `roster-filename`, `roster-size-bytes`, `evidence-note-md5`, `roster-sha1`, `evidence-note-copy-sha256` |
| Text (2) | `evidence-note-magic-prefix-hex-16`, `evidence-note-text-utf8-bom-present` |
| Days 4–7 (5) | `d04-jpeg-001-…`, `d05-png-001-…`, `d06-pdf-001-…`, `d07-zip-001-zip-eocd-total-entries`, `d07-zip-001-zip-central-directory-member-names` |
| PE (3) | `d09-pe-001-pe-coff-machine-u16-hex`, `…-address-of-entry-point-rva-hex`, `…-version-original-filename` |
| Days 12–15 (4) | `d12-dotnet-001-dotnet-mvid-guid`, `d13-msi-001-msi-product-code-guid`, `d14-lnk-001-lnk-target-path-windows`, `d15-ooxml-001-…` |
| Synthesis (1) | `metadata-day-15-synthesis-sha256-order` |

- Mastery: an outer ZIP with `evidence-01.zip` … `evidence-05.zip`, **5 sets × 20 = 100 questions**.

## Solution
**OOXML relationships.** A `.docx` is a ZIP. Every part may have a sibling `_rels/<part>.rels` XML listing
`<Relationship Id Type Target [TargetMode]>`. Internal targets are part names relative to the source part; external
ones (`TargetMode="External"`) are URLs or paths outside the package.

```python
for n in z.namelist():
    if n.endswith(".rels"):
        for r in ET.fromstring(z.read(n)).iter(NS_REL + "Relationship"):
            if (r.get("TargetMode") or "Internal").lower() == "external":
                ext.append(r.get("Target"))
answer = json.dumps(sorted(set(ext)), separators=(",", ":"))
```

The single document had two external targets, `https://example.test/evidence/<hex>` and
`https://example.test/control`. Submitted in document order: `incorrect`. Sorted, with `…/control` first: CORRECT.
Although the format says "exact values and order", the expected order is lexicographic.

**The synthesis question** reads: "Compute the full-file SHA-256 digest of each named file, then submit a compact JSON
array of their filenames in ascending digest order. Files: [...]". Hash each listed member of the set's container,
sort by hex digest, and emit the names:

```python
dig = [(hashlib.sha256(member(nm)).hexdigest(), nm) for nm in names]
answer = json.dumps([nm for _, nm in sorted(dig)], separators=(",", ":"))
```

**Filename questions** ("What is the exact filename of the roster / first evidence note / renamed evidence-note
copy?") have no `-> member` in their artifact field. The answer is the member of that set's container whose name
without extension equals the id stem (`roster`, `evidence-note`, `evidence-note-copy`). An older sibling-based rule
mapped `evidence-note-filename` to `evidence-note-copy.txt`; this was caught and fixed before submitting.
[Day 24](../day24/metadata-event-horizon.md) hardened it further.

**Porting.** The Day-14 solver had dropped the Day 4–7 extractors, because Days 10–14 asked only their own field.
They were ported back from [`day09/m9.py`](../solvers/day09/m9.py). `m15.py` dispatches every `Determine <field> for
<file>.` question through one `field_value()`, and the later `mNN.py` files extend it by monkey-patching.

## Time Trial & Mastery
- The timed modes were regular untimed attempts (`deadline: None`, `uar` 32). Computing all 20 answers took
  milliseconds, and Time Trial was CORRECT 20/20 on the first submit.
- Mastery: 100/100 CORRECT. `m15.py <id> start --save dir` keeps `start.json` plus the artifact, and
  `m15.py x none --dir <dir>` recomputes offline. This "save, inspect offline, then submit" loop stayed the lane's
  routine for the rest of the event.

## Lessons / gotchas
- "Exact values and order" can still mean *sorted*. When a JSON array has no natural order (relationship sets, file
  lists), probe sorted versus document order on the untimed single first.
- From here on, each timed metadata attempt contains one question for every file family since Day 1. A regression in
  any old extractor fails the whole set, so keep one solver and extend it rather than rewriting it.
- The single document's two URLs were the "document reaching somewhere it should not" (`/control`). It was never
  asked as a separate question.
