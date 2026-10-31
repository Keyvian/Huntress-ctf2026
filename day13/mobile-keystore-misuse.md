# 📱 Keystore Misuse

| | |
|---|---|
| **Day** | 13 |
| **Lane** | 📱 Mobile Android |
| **Challenge ID** | `mobile-android-day-13-keystore-misuse` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day13_quick/mob13.py`](../solvers/day13_quick/mob13.py) (= `mob12.py`, no logic changes) |

## Prompt
> Recover data protected by an app-controlled wrapping key despite nominal Keystore use.

## TL;DR
The APK layout is unchanged. The puzzle was `{"codec":"base64","data":"QU5TLTc3…"}` (`QU5TL` is the Base64 of
`ANS-`). Decoding it gives the answer. The Keystore and wrapping-key story is a decoy.

## Artifact
- Same APK shape as before. Mastery: 3 sets, one APK per set.

## Solution
**Theme.** "Nominal Keystore use": the app creates an AndroidKeyStore key but uses it to wrap a *data* key that it
also stores in the clear, or derives the wrapping key from app-controlled constants. The hardware-backed key then
protects nothing, and anyone with the app's files can unwrap the data.

**Extraction:** `base64.b64decode(data + "=" * (-len(data) % 4)).decode()`.

## Time Trial & Mastery
- This was the day the mode timing changed. The GM guidance began saying *"Time Trial and Mastery are regular
  scored challenges by default … Set `run_for_time:true` on start or retry to request a fresh timed Hall of Fame
  attempt."* Mobile's timed modes still carried deadlines on this day: **50 s** for Time Trial and **110 s** for
  Mastery, with `unique_attempts_remaining` 0.
- One process per mode finished in well under those budgets. All three modes passed on the first submit.

## Lessons / gotchas
- `QU5TL…` at the start of a string is Base64 of `ANS-`. That is a quick check when a new codec name shows up.
