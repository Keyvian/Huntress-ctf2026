# 📱 JNI Boundary

| | |
|---|---|
| **Day** | 16 |
| **Lane** | 📱 Mobile Android |
| **Challenge ID** | `mobile-android-day-16-jni-boundary` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day16_quick/mob15.py`](../solvers/day16_quick/mob15.py) (Day-15 solver, unchanged) |

## Prompt
> Identify a Java-to-native type or length assumption that changes backend authorization.

## TL;DR
This is the same APK family as [Day 15](../day15/mobile-native-library-secrets.md):
`{codec:"native", data:"ANS-…"}` plus `lib/x86_64/libarena.so`, whose `arena_value` symbol is the answer. The dex
story (`DAY-16:jni_length: Java-to-native validation mismatch`) and the backend are decoys. `mob15.py` solved
every mode without changes.

## Artifact
- Same members as Day 15. Time Trial artifact `jni_boundary_time_trial.apk`, Single Solve `jni_boundary.apk`.
- Mastery: 5 sets, one APK per set via the delivery fallback, with codecs `plain`, `xor`, `xor`, `base64`, `native`.

## Solution
**Theme.** JNI bugs at the boundary: Java passes a `String`/`byte[]` and the C side assumes a fixed length,
treats a `jint` as unsigned, or trusts `GetStringUTFLength` while copying `GetArrayLength` bytes. A truncated or
mismatched value then passes a native check that the Java layer would reject, and the backend sees "authorized".

**Extraction:** the Day-15 `native` branch, which reads the `.symtab` OBJECT `arena_value` from the challenge-owned
`.so` and cross-checks it against the JSON `data`.

## Time Trial & Mastery
- The GM guidance changed this day: *"Time Trial and Mastery are regular scored challenges by default. A correct
  untimed solve still earns the flag and CourseStack points. Set `run_for_time:true` on start or retry to request a
  fresh timed Hall of Fame attempt."* A plain `start` on the timed modes now returned `deadline: None`, so the
  one-process race was no longer needed for regular scoring. Listing entries now also carry `ranked_deadline_ms`,
  `ranked_pool_size` and `regular_pool_size`.
- `unique_attempts_remaining` was 32 for metadata and mobile. No rate limiting.

## Lessons / gotchas
- From this day on, the timed modes were played as regular untimed attempts. That left time to dry-run every
  mastery set locally before the one submit, which mattered from Day 23 on.
