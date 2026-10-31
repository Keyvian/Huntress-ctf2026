# 📱 Debug Me If You Can

| | |
|---|---|
| **Day** | 21 |
| **Lane** | 📱 Mobile Android |
| **Challenge ID** | `mobile-android-day-21-debug-me-if-you-can` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day21_quick/mob20.py`](../solvers/day21_quick/mob20.py) (Day-20 solver, unchanged) |

## Prompt
> Neutralize a clean-room anti-debug state machine while retaining the intended app flow.

## TL;DR
The Single Solve puzzle was `{"codec":"reverse","data":"<16 hex>-SNA"}`, and reversing it gives the answer. The
"anti-debug state machine" exists only as flavor: `classes.dex` holds `DebugMeIfYouCan` constants
(`CODEC="reverse"`, `CONTROL="anti_debug"`), `MainActivity` text and the usual WebView stub. `mob20.py` solved
every variant unchanged.

## Artifact
- Single Solve `debug_me_if_you_can.apk`, Time Trial `debug_me_if_you_can_time_trial.apk`.
- Mastery: 5 sets, one APK per set, with codecs `base64`, `split` (`order [2,0,1]`), `base64`, `reflection`,
  `reverse`.

## Solution
**Theme.** Anti-debug checks (`Debug.isDebuggerConnected()`, `ApplicationInfo.FLAG_DEBUGGABLE`, `TracerPid` in
`/proc/self/status`, timing checks) are often chained into a state machine, so patching one check breaks the flow.
"Retaining the intended app flow" means bypassing the checks without stubbing out the logic that produces the
result. The answer here doesn't depend on any of those checks.

**Extraction:** `data[::-1]`, then confirm the result matches `ANS-[0-9A-F]{16}`.

## Time Trial & Mastery
- The run took two passes. The 09:00 ET quick agent banked the warmups single and the **mobile single** around
  13:12 UTC, started the metadata single, and then stopped (its log stayed at 0 bytes). A manual re-run around
  13:55–14:10 UTC finished the remaining modes, including mobile Time Trial and Mastery. It resumed from the GM's
  solved flags and the saved attempts.
- All timed modes were regular untimed attempts (`deadline: None`). Time Trial `uar` 32.

## Lessons / gotchas
- A 0-byte group log plus some banked singles means the agent died mid-lane, not that the lane finished. Check
  `?op=list&day=N` before re-deriving anything.
