# 📱 Root of Trust

| | |
|---|---|
| **Day** | 22 |
| **Lane** | 📱 Mobile Android |
| **Challenge ID** | `mobile-android-day-22-root-of-trust` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day22_quick/mob20.py`](../solvers/day22_quick/mob20.py) (Day-20 solver, unchanged) |

## Prompt
> Model and bypass multiple synthetic root signals without globally patching success.

## TL;DR
The Single Solve puzzle was `{"schema":"huntress.mobile.puzzle.v1","day":22,"codec":"base64","data":"QU5TLTcy…"}`.
This was the last day on which every mode was a v1 puzzle. The root-detection theme is flavor only, and the APK
has the same shape as Day 21. `mob20.py` solved all three modes unchanged. The next day, the lane switched to
code analysis.

## Artifact
- `root_of_trust.apk`: `AndroidManifest.xml`, a 2.5 KB `classes.dex`, the puzzle asset and the v1
  `FIXTURE-.SF/.RSA` signature.
- Mastery: **6 sets** (catalog: 6 sets / 200 s), with codecs `plain`, `caesar`, `hex`, `base64`, `indexed` (a
  20-element permutation), `base64`.

## Solution
**Theme.** Root detection checks many signals (an `su` binary on `PATH`, `Build.TAGS` containing `test-keys`,
Magisk packages, writable `/system`, SELinux permissive, Play Integrity verdicts). "Without globally patching success"
means each signal has to be modeled and bypassed individually. Hooking `isRooted()` to return `false` is not
enough, because the app cross-checks the signals.

**Extraction:** `base64.b64decode(data + padding).decode()`.

## Time Trial & Mastery
- All timed modes were regular untimed attempts. Time Trial `uar` 32.
- Mastery grew to 6 sets. The decoder needed no change, because every codec in the mix had appeared before.

## Lessons / gotchas
- Mastery set count is the lane's clock: 3 (Days 1–7 and 10–14), 5 (Days 8–9 and 15–21), 6 (Day 22), then
  one more each day up to 15 on Day 31.
