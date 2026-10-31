# 📱 Cleartext Session

| | |
|---|---|
| **Day** | 08 |
| **Lane** | 📱 Mobile Android |
| **Challenge ID** | `mobile-android-day-08-cleartext-session` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | `d8mob.py` (session scratch, not preserved; the Day-5 universal decoder retargeted to Day 8). The equivalent is [`solvers/day09/mob9.py`](../solvers/day09/mob9.py) |

## Prompt
> Recover a synthetic session from allowed cleartext traffic and replay it against the backend.

## TL;DR
The APK container is unchanged. Single Solve used `codec:"reverse"`, the same as
[Day 2](../day02/mobile-deep-link-drift.md): the stored string `…-SNA` read backwards is the answer. Time Trial and
Mastery (now 5 sets) went through the same universal decoder once the GM stopped rejecting the attempt with
`training_rotation_invalid`.

## Artifact
- An APK with `assets/huntress_puzzle.json`. Single Solve: `{"codec":"reverse","data":"<16 hex>-SNA"}`.
- Time Trial: one `answer`. Mastery: `set1.answer` … `set5.answer`, one APK per set. This was the first mobile
  mastery with 5 sets (catalog: 5 sets, 170 s ranked budget).
- The codecs used in the Time Trial and Mastery variants were not logged, only the decoded answers.

## Solution
**Theme.** `android:usesCleartextTraffic="true"`, or a Network Security Config with
`cleartextTrafficPermitted="true"`, lets the app talk plain HTTP. Anyone on the path can then read session
cookies or bearer tokens and replay them. The "replay it against the backend" part of the prompt refers to the
usual decoy, the `127.0.0.1:19090` evidence endpoint embedded in the dex.

**Extraction.** Single Solve was decoded on the Windows host during the morning run, while the Homebase VM was
unreachable:

```python
answer = data[::-1]        # "6667…-SNA" -> "ANS-…7666"
```

## Time Trial & Mastery
- The first try at the timed modes failed. `start` returned `{"error":"training_rotation_invalid"}`, `retry`
  returned `start_required`, and `practice` returned `operation_not_allowed`. All three were server-side states, not
  wrong answers.
- About a minute later a re-test of `start` returned `answer_ids`. `d8mob.py time_trial mastery` then solved both on
  the first submit: Time Trial with 1 answer, Mastery with 5 answers in one batch.

## Lessons / gotchas
- When `start` returns an error like `training_rotation_invalid`, wait and retry the *start*. Don't change the
  solver. The decode was never the problem.
- Mastery set counts start growing here (3 → 5). Size the solver by `answer_ids`, not by a fixed number of
  deliveries.
