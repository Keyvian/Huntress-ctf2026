# 📱 Integrity Signals

| | |
|---|---|
| **Day** | 25 |
| **Lane** | 📱 Mobile Android |
| **Challenge ID** | `mobile-android-day-25-integrity-signals` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day25_quick/mob23.py`](../solvers/day25_quick/mob23.py) + patched [`dalvik.py`](../solvers/day25_quick/dalvik.py) (java.lang.reflect model) · cross-checks [`mobcheck25.py`](../solvers/day25_quick/mobcheck25.py), [`mobcheck25_d19.py`](../solvers/day25_quick/mobcheck25_d19.py) · tracer [`dbg_reflect.py`](../solvers/day25_quick/dbg_reflect.py) |

## Prompt
> Forge or replay a bounded challenge-owned integrity statement and explain the missing binding.

## TL;DR
Single Solve was a v1 **`hex`** puzzle. In the Time Trial v2 build, the integrity statement is just
`IntegritySignals.integrityStatement(a, b) = a ^ b` mixed into the token, so the value is again a pure function of the
DEX. Mastery (9 sets) brought back the **Day-19 "Reflection Maze" theme as v2 code**. That set dispatches through
`Class.forName(...).getDeclaredMethod("m" + k, Long.TYPE).invoke(null, …)`, so `dalvik.py` gained a
`java.lang.reflect` model. The independent hand port caught a real interpreter bug before the submit.

## Artifact
- Single Solve: `integrity_signals.apk`, v1 `hex`. Time Trial: `integrity_signals_time_trial.apk`, v2 `analysis`.
- Mastery: **9 sets**, one APK per delivery (labels `integrity_signals_mastery_01.apk` …; the default artifact is
  set 1), with themes d01, d04, d07, d10, d14, d16, **d19**, d22, d25.

## Solution
**Theme.** Integrity attestations (Play Integrity / SafetyNet verdicts, app-signed "I am genuine" statements) are
only as good as their *binding*. If the statement isn't bound to a server nonce, the request and the device key, it
can be replayed or forged. "Explain the missing binding" names that flaw. The computation itself has no binding to
anything outside the DEX.

**Time Trial chain** (from `mobcheck25.py`):

```
Release.code = SealCheck.finIntegrity…(Mix.f1(token())) ^ K
token        = VerdictMap.mixVerdict…(scanIntegrity…(mixIntegrity…(SEED)))
scanIntegrity: iS2 = Probe.s2(…), iS3 = Probe.s3(…)
               stmt = (long)(int) IntegritySignals.integrityStatement(iS2, iS3)    // a ^ b
               … xor/mul/add with constants, then * C
```

`dalvik.py` and the hand port agreed, and the Time Trial was `CORRECT`.

**Mastery set 7 (reflection).** The interpreter stopped with
`UnsupportedOpcode: library call Ljava/lang/Class;->forName`. jadx showed:

```java
// Util.routeMaze…: five hops, each one resolved by name at run time
Class.forName(…).getDeclaredMethod("m" + ReflectionMaze.dispatch(k), Long.TYPE)
     .invoke(null, Long.valueOf(j))
```

The fix models reflection over the DEX itself. A `Class` is its type descriptor (`Long.TYPE`-style statics map to
primitive descriptors through `PRIM_BOX`). A `Method`/`Field` is a tagged tuple. `Class.forName`,
`getDeclaredMethod`/`getMethod`/`getDeclaredField`/`getName`, `Method.invoke`/`setAccessible`, `Field.get*` and
`Object.getClass` are modeled. `reflect_invoke()` resolves the DEX method by class, name and parameter types and runs
it through `VM.invoke`, so the trace shows `Maze.m7[reflect]`.

**The bug the cross-check caught.** `invoke(null, …)` passes `null` as `const/4 0`, the integer 0, not Python `None`.
The first reflection shim saw a non-`None` receiver and prepended it, which dropped the real `long` argument, so the
route returned a constant. Staticness is now decided from the target's code item (`ins_size == parameter slots`),
never from the receiver value. After the fix the interpreter matched the hand port. In that port
(`mobcheck25_d19.py`), `dispatch(0) = 3` and `dispatch(1) = 7`, so the route is `m3(m7(m7(m3(m7(j)))))`. Mastery was
then re-downloaded, computed in 3.4 s and submitted once: `CORRECT`.

## Time Trial & Mastery
- All timed modes were regular untimed attempts. The listing advertised ranked budgets (mobile 50 s / 290 s), but
  regular untimed play still scored. Time Trial `uar` 32. No rate limiting.

## Lessons / gotchas
- Dalvik `null` is `const/4 0`. Any shim that branches on "receiver is None" is wrong.
- Mastery now re-uses OLD themes the v2 interpreter has never seen as v2 code. Expect more (split APKs, dynamic DEX…)
  and keep the independent re-implementation. It turned what would have been a wrong submit into a fixed interpreter.
- `dbg_reflect.py <apk>` traces the `Class`/reflect library calls of a method. That is the fastest way to see what
  a reflective route resolves to.
