# 📱 Backup Spill

| | |
|---|---|
| **Day** | 05 |
| **Lane** | 📱 Mobile Android |
| **Challenge ID** | `mobile-android-day-05-backup-spill` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | `d5mob_solve.py` on the Homebase VM (not preserved). The same `split` logic is in [`solvers/day09/mob9.py`](../solvers/day09/mob9.py) |

## Prompt
> Extract synthetic application state admitted by a flawed backup boundary.

## TL;DR
The APK container is unchanged, with a new codec **`split`**. The puzzle has no usable `data`. It carries a `parts`
list and an `order` list instead. Part `i` goes to output position `order[i]`, and joining the positions gives
`ANS-<16 HEX>`.

## Artifact
- Question: *"For case MOB-05-… in package com.huntress.mobile.d05.v…: Extract synthetic application state admitted
  by a flawed backup boundary. Submit only the exact backend answer code returned for this case."* The artifact is
  `backup_spill.apk` (12,704 bytes).
- `classes.dex` strings show the theme wiring: classes `BackupSpill`, `ChallengeActivity` and `MainActivity`,
  the descriptor `DAY-05:backup_store:backup-admitted SharedPreferences`, the case banner ("cross the backup-admitted
  SharedPreferences boundary"), and the usual `http://127.0.0.1:19090/…/evidence?case_id=…&client_secret=SECRET-…&proof=`
  WebView URL.
- The puzzle (values changed here) looks like this:
  `{"schema":"huntress.mobile.puzzle.v1","day":5,"codec":"split","data":"","parts":["CCCCCCCCC","ANS-A","BBBBBB"],"order":[2,0,1]}`

## Solution
**Theme.** `android:allowBackup="true"` (the default before Android 12), or a permissive
`fullBackupContent`/`dataExtractionRules`, lets `adb backup` or a device-to-device transfer copy the app's private
`shared_prefs/*.xml` and databases, including tokens the developer assumed would never leave the sandbox.

**Extraction.** The rule is a scatter:

```python
parts, order = p["parts"], p.get("order", list(range(len(p["parts"]))))
out = [None] * len(parts)
for i, o in enumerate(order):
    out[o] = parts[i]               # part i lands in slot order[i]
s = "".join(out)                    # ["CCCCCCCCC","ANS-A","BBBBBB"], [2,0,1] -> "ANS-A" "BBBBBB" "CCCCCCCCC"
if not ANS.fullmatch(s):            # the other reading is kept as a fallback
    s = "".join(parts[o] for o in order)
```

The `ANS-[0-9A-F]{16}` pattern decides which reading is right. On Day 5 the scatter reading was always correct.

## Time Trial & Mastery
- Time Trial had one answer on a ~7 s ranked timer, so start, fetch, decode and submit ran in one process.
- Mastery had 3 answers (`set1-3`). The deliveries were labeled `backup_spill_mastery_01.apk` … `_03.apk` (1-based
  labels, 0-based `delivery`). Our notes record this mastery as untimed.

## Lessons / gotchas
- `split` comes back many times: Day 10, in later mastery mixes, and on Day 26 with parts spread across split APKs.
  Keep both readings and let the answer pattern choose.
- `data` is an empty string for split puzzles, so a decoder that only reads `data` gets nothing.
