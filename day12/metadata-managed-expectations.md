# 🔎 Managed Expectations

| | |
|---|---|
| **Day** | 12 |
| **Lane** | 🔎 Metadata Forensics |
| **Challenge ID** | `metadata-forensics-day-12-managed-expectations` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day12_quick/m12.py`](../solvers/day12_quick/m12.py) |

## Prompt
> The .NET assemblies share names, versions, and source ancestry—but their module identities remain distinct. Separate rebuilds from renames.

## TL;DR
One field in every mode: `dotnet.mvid_guid`, the Module Version ID of a .NET assembly. The compiler generates a fresh
GUID on every build, so two builds of identical source still get different MVIDs, while a renamed copy keeps its
MVID. Read row 0 of the `Module` metadata table, follow its index into the `#GUID` heap, and print the 16 bytes as a
canonical lowercase GUID using .NET's mixed-endian layout.

## Artifact
- Answer id `d12-dotnet-001-dotnet-mvid-guid` (pattern: canonical 8-4-4-4-12 GUID) for `managed-NNN.dll` inside
  `metadata-day-12-evidence.zip`. The assemblies share an assembly name and version (for example
  `Huntress.Managed.<hex>` v2.0.2.6), which is the "rebuild vs rename" setup.
- Mastery: 2 sets in one ZIP.

## Solution
```python
pe = dnfile.dnPE(data=b)
m = pe.net.mdtables.Module.rows[0]
gh = pe.net.metadata.streams.get(b"#GUID")
i = m.struct.Mvid_GuidIndex                       # 1-based index into #GUID
raw = gh.__data__[16 * (i - 1):16 * i]
answer = str(uuid.UUID(bytes_le=bytes(raw))).lower()
```
- The `#GUID` heap is an array of 16-byte GUIDs indexed from **1**.
- GUIDs are stored in the Windows/.NET layout: the first three groups are little-endian. `uuid.UUID(bytes_le=...)`
  turns them into the familiar text form. Reading the bytes big-endian gives a wrong but plausible GUID.
- `dnfile`'s `Module.rows[0].Mvid` already yields the same string. The manual path is a cross-check.

`m12.py` also exposes `dotnet.module_name`, `assembly_name`, `assembly_version` and `assembly_culture`, in case the
"rebuild vs rename" story became questions. It never did. When a target member is missing it fetches further
deliveries.

## Time Trial & Mastery
Time Trial CORRECT in 1.7 s, Mastery (2 sets) CORRECT in 1.4 s, each one process from start to submit. No surprises.

## Lessons / gotchas
- Forensic meaning: same MVID means the same compiled module (a rename or copy); a different MVID with an identical
  name and version means a rebuild.
- Lowercase output was accepted. The field joins the compounding contract as `d12-dotnet-001-dotnet-mvid-guid` from
  [Day 15](../day15/metadata-a-word-to-the-wise.md) on.
- Compare [Day 13](../day13/metadata-product-placement.md), where the MSI GUID wanted the opposite convention:
  braces and uppercase.
