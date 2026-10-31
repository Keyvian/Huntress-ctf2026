# 🔎 Seeing Double

| | |
|---|---|
| **Day** | 30 |
| **Lane** | 🔎 Metadata Forensics |
| **Challenge ID** | `metadata-forensics-day-30-seeing-double` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day30_quick/m30.py`](../solvers/day30_quick/m30.py) + cluster module [`rel30.py`](../solvers/day30_quick/rel30.py) (per-set cross-check: [`check_m30.py`](../solvers/day30_quick/check_m30.py)) |

## Prompt
> The corpus is too large for manual browsing. Build a relationship map from exact identity, semantic identity, containment, and claimed provenance—then expose the fabricated cluster.

## TL;DR
The new field is `relation.identical_sha256_groups` for `cluster-001.zip`: every set of members whose bytes are
identical, as nested arrays of **artifact ids**. Ids are sorted within a group, groups are sorted, and only groups of
two or more count. The single proved the id form (filenames were `incorrect`). The timed variants then changed
**shape**: no manifest, anonymous names, and deliberate one-byte near-duplicates, one of which corrupts a nested
ZIP's CRC and crashed the old unzip helper.

## Artifact
Answer id `d30-cluster-001-relation-identical-sha256-groups`. Two cluster shapes appeared:

| | Single Solve | Time Trial / Mastery |
|---|---|---|
| Members | 30 files = 5 families × 6 | 20–39 members under `artifacts/` |
| Names | real filenames with extensions | anonymous, extensionless (`artifacts/drift-74`) |
| Manifest | truthful `delivery-manifest.json` (id = filename stem) | none |
| Groups | 5 duplicate families, no singletons | 2–5 duplicate groups + 4–31 singletons |
| Traps | — | one-byte near-duplicates: text like `$ErrorActjonPreference` or `meadow distant cioder`, or a flipped byte inside a nested ZIP's stored member |

Time Trial: **35 questions**. Mastery: **14 sets × 35 = 490**.

## Solution
Hash every member's real bytes and group by digest:

```python
by = collections.defaultdict(list)
for path, data in members(cluster):                       # all non-directory members except the manifest
    by[hashlib.sha256(data).hexdigest()].append(id_of(path))
groups = sorted(sorted(v) for v in by.values() if len(v) > 1)
answer = json.dumps(groups, separators=(",", ":"))       # [["amber-82","delta-78","fathom-42"],[...],...]
```

- `id_of(path)` is the manifest id when a manifest lists the path, otherwise the filename stem
  (`artifacts/drift-74` → `drift-74`).
- Groups are built from bytes only, never from the manifest's claimed `sha256` / `size_bytes`. `rel30.check_manifest()`
  still compares those claims with the real bytes and prints any `MANIFEST MISMATCH`.
- Near-duplicates must not merge. One flipped byte is a different SHA-256, so exact hashing handles them. Comparing
  decoded text, normalized content or the *inner* content of nested ZIPs would merge them by mistake.

**How the conventions were proven:**

- Single: filenames with extensions were graded `incorrect`, and ids were CORRECT.
- The sort order and the "no singletons" rule were proven separately on the time trial. A **one-answer subset
  submit** came back `accepted` with `remaining: 34`, which banked the answer and confirmed the convention before the
  rest went in.

**Crash fixed.** A flipped byte inside a nested ZIP's stored member breaks that inner member's CRC.
`m15.unzip_all` recursed into every ZIP and died with `BadZipFile: Bad CRC-32 for file 'island.txt'`. `m30.unzip_all`
logs `UNREADABLE MEMBER` and continues. Nothing is lost, because the outer artifact's bytes are what get hashed. This
happened to 1 member in the time trial and 5 in mastery.

## Time Trial & Mastery
Regular untimed attempts. Before the mastery submit, `check_m30.py` recomputed every set from its own
`evidence-NN.zip` and compared it with the solver's answers: 14/14 equal. Single CORRECT, Time Trial CORRECT 35/35,
Mastery CORRECT 490/490.

## Lessons / gotchas
- Single and timed variants can differ in *shape*, not only in values. A solver that trusted the single's manifest
  or file layout would have failed every timed set.
- Exact identity means identical bytes. The prompt's "semantic identity", "containment" and "claimed provenance"
  never became questions. Treating any of them as identity would have merged the near-duplicates.
- A recursive unzip in a forensic pipeline must tolerate damaged members. Corrupted evidence is part of the evidence.
- Probe new conventions with a one-answer subset submit. It banks on success and costs nothing on failure.
