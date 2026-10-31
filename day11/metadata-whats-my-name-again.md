# 🔎 What’s My Name Again?

| | |
|---|---|
| **Day** | 11 |
| **Lane** | 🔎 Metadata Forensics |
| **Challenge ID** | `metadata-forensics-day-11-whats-my-name-again` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day11_quick/m11.py`](../solvers/day11_quick/m11.py) (+ dump tool [`verinfo.py`](../solvers/day11_quick/verinfo.py)) |

## Prompt
> Filenames have been randomized, but Windows version resources remember what the binaries called themselves. Recover the original identities and expose the impersonator.

## TL;DR
One field in every mode: `pe.version_original_filename`, the `OriginalFilename` string from the PE's
`VS_VERSIONINFO` resource. `pefile` with the resource directory parsed reads it directly. Values look like
`pe-base-386.exe`, `pe-base-amd64.exe` and `pe-base-arm64.exe`, and they show the original build name behind the
randomized `telemetry-agent-NNN.exe` label.

## Artifact
- Answer id `d09-pe-NNN-pe-version-original-filename`, again the [Day 9](../day09/metadata-built-different.md) PE
  family (`telemetry-agent-NNN.exe`, Go-built, i386 / amd64 / arm64 variants) inside `metadata-day-11-evidence.zip`.
  Mastery: 2 sets.
- The version resource has one StringFileInfo table, language/codepage `040904b0`, with `CompanyName`
  (Huntress Labs), `FileVersion` (1.0.0.0), `OriginalFilename`, `ProductName` (Huntress Metadata Forensics) and
  `ProductVersion` (2026.10.1.0). There is no `InternalName` and no `FileDescription`.

## Solution
```python
pe = pefile.PE(data=b, fast_load=True)
pe.parse_data_directories(
    directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
for fi in pe.FileInfo or []:
    for e in fi:
        for t in getattr(e, "StringTable", []):
            v = t.entries.get(b"OriginalFilename")
            if v: answer = v.decode()
```
`m11.py` generalizes this to any `pe.version_<snake_case>` question. It maps `original_filename` →
`OriginalFilename` case- and underscore-insensitively, so a later `product_version` or `company_name` question would
need no new code. It keeps all of [Day 10](../day10/metadata-where-do-we-begin.md)'s header fields. `verinfo.py` dumps
the StringFileInfo, FixedFileInfo and VarFileInfo of every PE in a (nested, possibly AES) ZIP, which helps when
checking a new variant by eye.

## Time Trial & Mastery
- Time Trial: CORRECT in 1.55 s (one-process start → fetch → parse → submit, `uar` = 1). Mastery (2 sets): CORRECT
  in 1.5 s.
- New this day: three headless agents (quick / script / binary lanes) shared one GM token, and the first `op=list` /
  `op=status` calls came back `{"error":"rate_limited"}`. The shared helper `gmx.GMX` now retries post, status and
  artifact calls with exponential backoff (1.5 s × 1.6, capped at 10 s). No timed mode was affected.

## Lessons / gotchas
- The `OriginalFilename` is what the linker or resource compiler stamped at build time. Renaming the file on disk does
  not change it. That is the forensic point the prompt is making.
- The "impersonator" never became a separate question.
- Returns in every compounding attempt from [Day 15](../day15/metadata-a-word-to-the-wise.md) on as
  `d09-pe-001-pe-version-original-filename` (`pe-base-386.exe` in the cumulative bundle).
