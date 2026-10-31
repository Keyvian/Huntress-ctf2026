# 🔎 Main Character Energy

| | |
|---|---|
| **Day** | 22 |
| **Lane** | 🔎 Metadata Forensics |
| **Challenge ID** | `metadata-forensics-day-22-main-character-energy` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day22_quick/m22.py`](../solvers/day22_quick/m22.py) + JAR manifest parser [`jar.py`](../solvers/day22_quick/jar.py) |

## Prompt
> Java archives contain libraries, applications, and nested dependencies whose manifests disagree with their launchers. Determine what is runnable and where execution begins.

## TL;DR
The new field family is `jar.*`, and the only field asked was `jar.main_class` for `application-001.jar`: the
`Main-Class` attribute of `META-INF/MANIFEST.MF`, here `arena.evidence.ArtifactMain`, whose class file is present in
the JAR. The single was banked at once from a manual read of the bytes. The resolver module came afterwards, for the
cumulative timed modes.

## Artifact
- `application-001.jar` (1,146 bytes): `META-INF/MANIFEST.MF`, `arena/evidence/ArtifactMain.class`,
  `evidence/header.bin`, `evidence/marker.txt`. The same JAR appeared in the single, the time trial and all six
  mastery sets.
- Answer id `d22-jar-001-jar-main-class`.
- Time Trial: **27 questions** (the cumulative contract through `apk.package_name`, plus `jar.main_class` and the
  synthesis question, which now includes `application-001.jar`). Mastery grew to **6 sets × 27 = 162**.

## Solution
Parse the manifest the way the JAR spec defines it, not with a line grep:

- Lines are at most 72 bytes. A line that starts with a single space continues the previous one, so long class names
  can be split across lines.
- The main section comes first. Per-entry sections (`Name: …`) follow, separated by blank lines.
- Attribute names are case-insensitive.

A simplified sketch of what `jar.py` does for the main section:

```python
def manifest_main(text):
    lines, out = [], {}
    for raw in text.replace("\r\n", "\n").split("\n"):
        if raw.startswith(" ") and lines: lines[-1] += raw[1:]      # continuation
        elif raw == "": break                                       # end of main section
        else: lines.append(raw)
    for ln in lines:
        k, _, v = ln.partition(":")
        out[k.strip().lower()] = v.strip()
    return out
answer = manifest_main(z.read("META-INF/MANIFEST.MF").decode())["main-class"]
```

`jar.py` answers many more `jar.<snake>` fields, prepared for the launcher / nested-dependency story:

- `runnable`: `Main-Class` present *and* its `.class` in the JAR, or a Spring-Boot-style launcher with `Start-Class`.
- `entry_point` / `entry_class` / `execution_begins`: `Start-Class` when `Main-Class` is a known launcher, otherwise
  `Main-Class`.
- `main_class_exists`, `launcher`, `class_count`, nested JAR count and list, `manifest_sha256`.
- Any manifest attribute by snake → Header-Case (`created_by` → `Created-By`, `class_path`, `premain_class`, …).

None of them was asked.

## Time Trial & Mastery
- Single: CORRECT, submitted with `m21.py --override id=value` before `jar.py` existed.
- Time Trial: CORRECT 27/27. Mastery: CORRECT 162/162. The whole quick group (warmups + metadata + mobile) took about
  3 minutes wall clock.

## Lessons / gotchas
- Bank a new family's single from a manual read (`--override`) as soon as it is understood, then write the general
  resolver and test it offline on the saved time-trial directory (`--dir`) before the cumulative submits.
- A prompt that promises launcher and nested-JAR disagreement may still ask only the plain manifest field. Implement the
  obvious field first.
