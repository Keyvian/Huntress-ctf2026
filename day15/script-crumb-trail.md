# 📜 Crumb Trail

| | |
|---|---|
| **Day** | 15 |
| **Lane** | 📜 Script Analysis |
| **Challenge ID** | `script-analysis-day-15-credential-store-clues` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day15_script/s9.py`](../solvers/day15_script/s9.py) (syntax-true Batch expansion) · [`timed.py`](../solvers/day15_script/timed.py) (legacy fallback) · [`batshapes.py`](../solvers/day15_script/batshapes.py) (new) |

## Prompt
> Some credential-access-shaped code keeps rummaging through the browser's cupboards, and synthetic store artifacts are sitting there waiting. Connect each code path to the artifact it targets, and find the reference that points at a store that was never there.

## TL;DR
**1,026 questions** = the Day-14 contract (971, unchanged) + 55 new: four **Perl** polyglots and a Perl CGI
host fixture. The new files were trivial. Two other things made this day notable. First, the timed modes now
started as **untimed** regular play by default, so a wrong full submit no longer burned the attempt. Second,
the Time Trial grader rejected the long-standing Batch `expansion` convention and wanted **syntax-true**
labels. The classifier was fixed on the same attempt, and Mastery (now **5 sets**, 5,130 answers) passed in one shot.

## Artifact
WinZip-AES ZIP (`infected`). New files:

| File | Questions | Notes |
|---|---|---|
| `polyglot-perl-{benign-utility,downloader,launcher,staged-chain}.pl` | 4 × 11 | campaign `PERL-<8hex>` |
| `host-perl-cgi-perl.pl` | 11 | `host_profile=perl_cgi`, role `staged_chain`, attack `T1059` |

No new Bash fixtures. No question referred to credential stores or a missing store.

## Solution
### New files (no code change)
`qdiff.py` → 0 gone, 0 changed, 55 new. The generic `HUNTRESS_ANALYSIS_V1` decoder handled `.pl` as-is,
and the host fixture went through the existing `host-` branch. Role and attack were read from the descriptor
([Day 8](../day08/script-lost-in-translation.md)). Single Solve: Perl groups banked first (5 × 11
`accepted`), then 10-file batches, the last one CORRECT.

### Batch `-expansion`: from convention to syntax
The question wording had been stable since at least Day 14: "percent, delayed, call_double, for_indirect…
classify only the descriptor reconstruction statement". The convention used since
[Day 4](../day04/script-dim-and-dimmer.md)/[Day 9](../day09/script-all-the-world-s-a-stager.md) (`%%h` in a
`call set` → `call_double`; `for … do call set` → `for_indirect`; everything else → `delayed`) was still
accepted on today's Single Solve. On **today's Time Trial**, 8 of the 9 Batch files were rejected. The grader
wanted the label that matches the syntax of the reconstruction statement:

| Reconstruction statement | Label |
|---|---|
| `set "x=%a%%b%…"` | `percent` |
| `call set "x=%%a%%%%b%%…"` (any variable name) | `call_double` |
| `set "x=!a!!b!…"` | `delayed` |
| `for %%G in (…) do call set …` | `for_indirect` |

```python
for l in region.splitlines():                     # region = the inspect block
    if re.search(r'(?i)\bset\s+"?neutral|HUNTRESS_READY=', l) or re.match(r'(?i)\s*echo', l):
        continue                                  # skip decoys and guards
    m = re.search(r'(?i)\bset\s+"?\w+=(.*)$', l)
    if not m: continue
    if re.search(r'(?i)\bfor\s+%%\w+\s+in\s*\([^)]*\)\s*do\s+call\s+set', l): exp = "for_indirect"; break
    if len(re.findall(r'%%\w+%%|%\w+%|!\w+!', m.group(1))) < 2: continue   # not the reassembly line
    exp = ("call_double" if re.search(r'(?i)\bcall\s+set\b', l) and "%%" in m.group(1)
           else "delayed" if re.search(r'!\w+!', m.group(1)) else "percent")
    break
```

The one specimen with a real `!x!` reconstruction had been right under both rules. **Control** stayed on the
legacy classifier. A one-iteration `for /l %%Q in (1,1,1) do call :HUNTRESS_RECOVER` wrapper was accepted as
`call_subroutine`, even though the wording suggests a "for_once"-style label.

`s9.py` now defaults to the syntax-true rule (`S9_BATCH_LEGACY=1` switches back), and `timed.py`
automatically re-banks any wrong `.cmd`/`.bat` group with the legacy labels. `batshapes.py <dirs…>` dumps
each file's reconstruction region next to the submitted and current labels for debugging. The syntax-true
default was then accepted in all three modes on every remaining day.

## Time Trial & Mastery
- **New default: untimed.** The start response had `deadline: None` and `run_for_time: False`. The guidance
  said Time Trial and Mastery are regular scored challenges by default, and that `run_for_time: true` opts
  into a timed Hall-of-Fame attempt. So a wrong full submit no longer cost anything. The bad groups were
  rebanked on the same attempt (`s9.py <ch>/time_trial --submit --by-file --only <regex>`).
- Time Trial: full submit `incorrect` → per-file banking showed 8 of 9 Batch files wrong → classifier fixed
  → the 8 groups resubmitted on the same attempt; the last one CORRECT.
- **Mastery grew to 5 sets** (5,130 answers), all in the default artifact. One full submit in 7.7 s →
  CORRECT. The guidance suggested chunks of at most 500 answers or 512 KiB, but the 5,130-answer single
  submit was accepted.

## Lessons / gotchas
- A grader can tighten the interpretation of an unchanged question between modes or days. Keep both the old
  and the new classifier and let banking pick per group.
- The decoys in the inspect block (`neutral` sets, `HUNTRESS_READY` guards, `echo` lines) must be skipped,
  or the classifier reads the wrong statement.
- With untimed regular attempts, the by-file banking used for Single Solve also works for debugging Time
  Trial and Mastery.
- Previous: [Day 14](../day14/script-trust-the-process.md) · Next: [Day 16](../day16/script-same-same-but-different.md).
