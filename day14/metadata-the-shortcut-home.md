# 🔎 The Shortcut Home

| | |
|---|---|
| **Day** | 14 |
| **Lane** | 🔎 Metadata Forensics |
| **Challenge ID** | `metadata-forensics-day-14-shortcut-home` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day14_quick/m14.py`](../solvers/day14_quick/m14.py) + shell-link parser [`lnk.py`](../solvers/day14_quick/lnk.py) |

## Prompt
> A shortcut collection is a map of intent—if you read where each link points instead of where it sits. Reconstruct the targets and identify the impossible destination.

## TL;DR
One field in every mode: `lnk.target_path_windows`, the target path of a Windows `.lnk` shortcut. The agent wrote a
pure-Python MS-SHLLINK parser. The answer is LinkInfo's `LocalBasePath` (plus `CommonPathSuffix`), which agreed with
the path rebuilt from the shell-item IDList: `C:\Windows\System32\cmd.exe`.

## Artifact
- Answer id `d14-lnk-001-lnk-target-path-windows` for `shortcut-NNN.lnk` inside `metadata-day-14-evidence.zip`.
  Mastery: `-01.zip` and `-02.zip` inside the default artifact.
- Each shortcut is a 547-byte MS-SHLLINK file with `LinkFlags = 0x97`: HasLinkTargetIDList, HasLinkInfo, HasName,
  HasWorkingDir, IsUnicode.
  - IDList: My Computer → `C:\` → `Windows` → `System32` → `cmd.exe`.
  - LinkInfo: VolumeID DRIVE_FIXED, serial `0xa1b2c3d4`, label `HUNTRESS`; LocalBasePath
    `C:\Windows\System32\cmd.exe`, empty suffix.
  - StringData: Name `Huntress deterministic shell-link evidence <12 hex>`, WorkingDir `C:\Windows\System32`.
  - No ExtraData blocks.
- All four shortcuts seen (001–004) had the same target, so the "impossible destination" never became its own question.

## Solution
Parse the structure in order: the 76-byte `ShellLinkHeader`, the optional `LinkTargetIDList`, the optional
`LinkInfo`, the optional `StringData` (UTF-16 when IsUnicode is set), then ExtraData blocks. Each optional part is
gated by its flag bit.

```python
def lnk_target(L):                  # L = lnk.LNK(member_bytes)
    c = L.target_candidates()       # one candidate per structure that can name a target
    for k in ("linkinfo_local", "linkinfo_network", "idlist", "vista_idlist", "environment", "relative_path"):
        if c.get(k):
            return c[k]
    return "none"
```

`lnk.py` covers more than this day needed:

- Header: flags, file attributes, three FILETIMEs, size, icon, show command, hotkey.
- IDList shell items: root GUID, volume, file and directory long names from the `BEEF0004` extension block, network
  and URI items.
- LinkInfo: VolumeID, local, network and Unicode paths.
- StringData.
- ExtraData: environment, Darwin, icon environment, tracker (machine id, droids, MAC), special/known folder, shim,
  Vista IDList.

Absent fields return `none`.

## Time Trial & Mastery
- Every timed mode this day had a **30 s** deadline (`ranked_deadline_ms: 30000`, `uar` 0); the warmup timed modes,
  untimed the day before, were timed again.
- Time Trial CORRECT (1.5 s), Mastery CORRECT (2 sets, 1.5 s).

## Lessons / gotchas
- A shortcut can name its target in several places (LinkInfo local path, LinkInfo network path, IDList, Vista
  IDList, environment-variable block, relative path). Real-world tampering makes them disagree, and that disagreement is what the
  "impossible destination" story was about. Compute every candidate and print them all, even when only one is asked.
- Joins the compounding contract as `d14-lnk-001-lnk-target-path-windows` from
  [Day 15](../day15/metadata-a-word-to-the-wise.md) on.
  The JSON-escaped form in the answer payload is `C:\\Windows\\System32\\cmd.exe`, a single backslash once decoded.
