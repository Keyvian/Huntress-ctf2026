# 🔎 Product Placement

| | |
|---|---|
| **Day** | 13 |
| **Lane** | 🔎 Metadata Forensics |
| **Challenge ID** | `metadata-forensics-day-13-product-placement` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day13_quick/m13.py`](../solvers/day13_quick/m13.py) + MSI reader [`msi.py`](../solvers/day13_quick/msi.py) |

## Prompt
> Installers were copied, renamed, and repackaged. Recover stable product identities, distinguish revisions from different products, and find the collision.

## TL;DR
One field in every mode: `msi.product_code_guid`, the `ProductCode` property of a Windows Installer package. No MSI
tooling was available in WSL, so the agent wrote a small pure-Python MSI database reader on top of `olefile`. The
answer is the `Property` table value **verbatim**: braces and uppercase, `{DD1A80D5-…}`.

## Artifact
- Answer id `d13-msi-001-msi-product-code-guid` for `installer-NNN.msi` inside `metadata-day-13-evidence.zip`.
  Mastery: `-01.zip` and `-02.zip`, one MSI per set, both inside the default artifact.
- The MSIs were built by msitools 0.103. All four installers seen (001–004) were byte-identical copies with the same
  ProductCode, UpgradeCode, ProductVersion 1.13.0 and package code (Summary Information `revision_number`). The
  "revisions vs different products / collision" story never turned into separate questions.

## Solution
An MSI is an OLE compound file whose streams hold a small relational database:

1. **Stream names** are compressed: characters `0x3800–0x47FF` each pack two characters from a 64-symbol alphabet,
   `0x4800–0x483F` pack one, and `0x4840` is the `!` table prefix. `msi.decode_name()` undoes this.
2. **String pool**: `_StringPool` (codepage header, then a (length, refcount) pair per string) plus `_StringData` (the
   concatenated bytes). String references in tables are 2 or 3 bytes wide, depending on a flag in the pool header.
3. **Schema**: `_Columns` lists table, column number, name and type for every table. Tables are stored
   **column-major**. Integer cells are biased by `0x8000` (2-byte) or `0x80000000` (4-byte).
4. Read the `Property` table and return the row whose `Property` is `ProductCode`.

```python
m = msi.MSI(member_bytes)
props = {r["Property"]: r["Value"] for r in m.table("Property")}   # m.properties() does the same
answer = props["ProductCode"]          # e.g. "{DD1A80D5-…}", returned verbatim
```

`m13.py` also maps generic `msi.<snake>` fields: any Property (case- and underscore-insensitive), `package_code` →
Summary `revision_number`, and `template` / `platform` → Summary `template`. These were meant for follow-up questions
that never came.

## Time Trial & Mastery
- Format probing on Single Solve: the style loop's first candidate (no braces) produced no output, so the log does not
  show whether the bare form would have been accepted. The braces-uppercase value was CORRECT, and `m13.py` defaults
  to `GUID_STYLE=braces_upper`.
- Time Trial CORRECT (1.3 s), Mastery CORRECT (2 sets, 1.1 s).
- Mode timing changed this day. The GM guidance now says Time Trial and Mastery are "regular scored challenges by
  default" and a timed Hall of Fame run needs `run_for_time:true`. Metadata timed modes still came back with deadlines
  (50 s time trial, 80 s mastery) and `uar` 0.

## Lessons / gotchas
- Report identifiers in their native form. MSI properties store the GUID with braces and uppercase, and that exact
  string was accepted. The .NET MVID on [Day 12](../day12/metadata-managed-expectations.md) went the other way:
  canonical lowercase without braces.
- ProductCode identifies the product version, UpgradeCode the product family, and the package code (Summary
  `revision_number`) the specific `.msi` file. That trio is what the prompt's story was about.
- Joins the compounding contract as `d13-msi-001-msi-product-code-guid` from [Day 15](../day15/metadata-a-word-to-the-wise.md) on.
