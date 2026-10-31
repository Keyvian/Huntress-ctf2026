# 📱 Hook Line and Signal

| | |
|---|---|
| **Day** | 23 |
| **Lane** | 📱 Mobile Android |
| **Challenge ID** | `mobile-android-day-23-hook-line-and-signal` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day23_quick/mob23.py`](../solvers/day23_quick/mob23.py) + [`dalvik.py`](../solvers/day23_quick/dalvik.py) (pure-Python Dalvik interpreter) + [`native.py`](../solvers/day23_quick/native.py) (JNI via Unicorn) |

## Prompt
> Separate real instrumentation signals from generated false positives.

## TL;DR
This is the day the lane changed. Single Solve was still a v1 puzzle (`xor`, key 81). Time Trial and Mastery shipped
a **new schema, `huntress.mobile.puzzle.v2`, with `codec:"analysis"` and no `data` field**. The answer is now
whatever `Release.code(Context)` in `classes.dex` *computes*: a chain of 64-bit mixers, brute-force "probe" loops
and a theme-specific signal function, ending in 16 hex digits after `ANS-`. "False positives" are the `seal*`
functions and `K*` constants that are never called. The agent wrote a **pure-Python Dalvik bytecode interpreter**
(`dalvik.py`) to compute the value without running the APK. For one mastery set whose code calls a JNI method, it
emulated a 88-byte x86-64 function from `libarena.so` in a **Unicorn** sandbox.

## Artifact
- Single Solve (`hook_line_and_signal.apk`, 12,704 bytes): `AndroidManifest.xml` (3,524), `classes.dex` (2,604),
  `assets/huntress_puzzle.json` (108, `{"schema":"huntress.mobile.puzzle.v1","day":23,"codec":"xor","data":"EB8C…","key":81}`)
  and the v1 signature files.
- Time Trial: `assets/huntress_puzzle.json` = `{"schema":"huntress.mobile.puzzle.v2","day":23,"codec":"analysis","build":"<12 hex>"}`.
  The dex classes are `ChallengeActivity`, `MainActivity`, `Release`, `Util`, `Mix`, `Probe`, `HookLineAndSignal`,
  `HookScan` and `TrampolineMap`, all under `com.huntress.mobile.d23.v<12 hex>`.
- Mastery: **7 sets**, one APK per delivery (default artifact + `delivery=1..6`), each a v2 build of an *earlier*
  day's theme: packages `d02`, `d06`, `d10`, `d14`, `d15`, `d22`, `d23`. The `d15` APK also ships
  `lib/x86_64/libarena.so` (13,512 bytes).

## Solution
### What the app does
jadx on the Time Trial dex shows the same `ChallengeActivity` every APK had, now with a gate:

```java
String answer = intent.getStringExtra("answer"), caseId = intent.getStringExtra("case_id");
if (intent.getData() != null) { answer = uri.getQueryParameter("answer"); caseId = uri.getQueryParameter("case_id"); }
if (Release.proof(this).equalsIgnoreCase(answer)) {
    String code = Release.code(this);
    // shows "Evidence released: " + code and loads
    // http://127.0.0.1:19090/mobile/attempt/<id>/evidence?case_id=…&client_secret=SECRET-…&proof=<code>
}
```

The "backend answer code" is `Release.code()`. The loopback backend is still unreachable and unnecessary. The smali
of `code()` shows the final step is the same in every v2 build:

```
token() -> Mix.f1(J) -> Util.fin<Theme>(J) -> xor-long with const-wide K
"ANS-" + "0123456789ABCDEF".charAt((v >>> s) & 0xF) for s = 60, 56, …, 0
```

`token()` starts from a constant seed and goes through a few `mix*` functions (xor, multiply, rotate, add with 64-bit
constants) and a `scan*` function. The scan calls `Probe.s1/s2/s3`, which are brute-force searches over 0..4095:

```python
def s1(a, b, c, d):                       # Probe.s1
    return next((x for x in range(4096) if (((x * a) + b) ^ c) & 4095 == d), -1)
def s2(a, b, c, d):                       # Probe.s2
    return next((x for x in range(4096) if ((((x ^ c) * a) + b) & 4095) == d), -1)
```

The results feed the theme's "signal" function. On Day 23 that is
`HookLineAndSignal.instrumentationSignals(a, b, c) = (a ^ b ^ c) & 7`, multiplied by a constant and mixed in. The
`seal*` methods (`HookScan.sealHook…`, `TrampolineMap.sealTrampoline…`, `Util.sealHook…`) look just as important,
but nothing calls them. They are the generated false positives.

### Interpreting instead of executing
`dalvik.py` parses the DEX (strings, types, protos, fields, methods, `class_data`, `code_item`s, `static_values`) and
runs the static methods on a register machine with Java `int`/`long` wrap-around semantics:

```python
while pc < n:
    op = b[pc]; hi = b[pc + 1]; A, B = hi & 0xF, hi >> 4
    if op in (0x01, 0x04, 0x07): R[A] = R[B]; pc += 2; continue          # move / move-wide / move-object
    if op == 0x18: R[hi] = i64(pc + 2); pc += 10; continue              # const-wide
    if op == 0x1a: R[hi] = dex.strings[u16(pc + 2)]; pc += 4; continue  # const-string
    ...                                                                  # if-*, cmp-long, binops (/2addr, /lit8, /lit16),
    raise UnsupportedOpcode("opcode 0x%02x at %d in %s->%s" % (op, pc, cname, mname))
```

It covers moves, consts, `goto`, `if-*`, `cmp-long`, all int/long binops, casts, `sget`/`sput` (with lazy
`<clinit>`), `invoke-static/direct/virtual` (+`/range`), packed/sparse switch, and a small JDK model
(`StringBuilder`, `String`, `Long/Integer.toHexString`, `Math`). The entry point is `Release.code`, or failing that
whichever method loads the `"ANS-"` string. **Unknown opcodes raise instead of guessing.** `vm.trace` records which
methods ran, so the decoys show up as "never called":

```
RESULT ANS-E4F6… valid steps 115728
called: Release.token, Util.mixTrampoline79, Util.scanSignal61, Probe.s3, Probe.s2,
        HookLineAndSignal.instrumentationSignals, HookScan.mixPatcheb, Mix.f1, Util.finTrampoline2d
never called (decoys): HookScan.sealHook1e, TrampolineMap.sealTrampolinec7, Util.sealHook30
```

The first run hit a DEX-parser index bug, which was fixed. The fixed interpreter's Time Trial value was submitted and
was `CORRECT`.

### The JNI set
Running the 7 mastery APKs locally exposed two gaps before anything was submitted:
1. The `d02` build failed with `opcode 0x23` (`new-array`) in `Util.mergeLink…`, so arrays were added
   (`new-array`, `fill-array-data`, `aget`/`aput`).
2. The `d15` build ("Native Library Secrets" theme) failed with `library call Ljava/lang/System;->loadLibrary`. Its
   token passes through `NativeLibrarySecrets.nativeShare(long)`, a `native` method. `native.py` finds the mangled
   export `Java_com_huntress_mobile_d15_v…_NativeLibrarySecrets_nativeShare` in `.dynsym`/`.symtab`, maps only the
   ELF `PT_LOAD` segments at a fixed bias into a Unicorn x86-64 CPU, sets up a scratch stack, a zero page for
   `JNIEnv*`/`jclass` and a return sentinel, puts the `jlong` in `rdx`, and runs until the sentinel. Syscalls,
   interrupts and unmapped accesses raise. The function is 88 bytes of `mov`/`movabs`/`add`/`xor`/`rol`/`shr`/`imul`.
   A hand transcription of its arithmetic gave the same output for a test input.

After both fixes, `mob23.py --local` reported 7/7 valid answers, and the mastery submit (4.3 s compute) was `CORRECT`.

## Time Trial & Mastery
- Every timed mode was a regular untimed attempt (`deadline: None`). Time Trial `uar` 32.
- `mob23.py` only submits if every answer matches `ANS-[0-9A-F]{16}`. The local run printed `SOME INVALID - not
  submitting` twice before the fixes, which saved two wrong mastery submits.
- v1 puzzles still go through the old decoders (`mob20` → `mob19`), so one entry point handles both schemas.

## Lessons / gotchas
- "Analysis" puzzles mean computing what the app computes. Interpret the DEX and emulate JNI in a sandbox. Never
  install or run the APK.
- An interpreter that fails loudly is the safety net. Every unmodeled feature (arrays, JNI, later reflection, split
  APKs, class loaders) showed up as an exception during the local dry run, not as a wrong answer.
- Mastery mixes v2 rebuilds of *older* themes, so each new day can pull in a feature the interpreter has never seen.
  Run every saved mastery APK locally before submitting.
- Use absolute paths with the Kali `jadx` wrapper. `apktool d` + smali is the ground truth when jadx's Java looks
  ambiguous (see [Day 29](../day29/mobile-white-box-key-recovery.md)).
