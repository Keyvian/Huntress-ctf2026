# 📱 Emulator Alibi

| | |
|---|---|
| **Day** | 24 |
| **Lane** | 📱 Mobile Android |
| **Challenge ID** | `mobile-android-day-24-emulator-alibi` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day24_quick/mob23.py`](../solvers/day24_quick/mob23.py) + [`dalvik.py`](../solvers/day24_quick/dalvik.py) · cross-check [`mobcheck24.py`](../solvers/day24_quick/mobcheck24.py) |

## Prompt
> Defeat app-owned environment checks on the same pinned emulator used by the solve oracle.

## TL;DR
Single Solve was a v1 **`split`** puzzle. Time Trial and Mastery were v2 `analysis` puzzles, as on
[Day 23](../day23/mobile-hook-line-and-signal.md). The emulator detection is decorative: the theme function is
`EmulatorAlibi.emulatorScore(a, b, c) = (a + b + c) % 4` over `Probe` results, with no `Build.*`, no system
properties and no JNI environment reads. The answer is a pure function of the DEX constants. `dalvik.py` computed it
without changes, and an independent hand port of the jadx output gave the same value before submitting.

## Artifact
- Single Solve: `emulator_alibi.apk` with `{"codec":"split","parts":[…],"order":[…]}`.
- Time Trial: a v2 build (`build` `3d2f…`) with the usual `Release` / `Mix` / `Probe` / `Util` classes plus
  `EmulatorAlibi`.
- Mastery: **8 sets**, all in the default artifact, one v2 build per earlier theme: intent injection (d04),
  provider grant, trust-everyone (d10), network-config split, the d15 JNI `NativeLibrarySecrets.nativeShare` (through
  Unicorn), an obfuscated `a.a`/`a.b` alias collapse, d23 hook/signal and d24 emulator alibi.

## Solution
**Theme.** Apps detect emulators through `Build.FINGERPRINT`/`MODEL`/`HARDWARE` (`generic`, `goldfish`,
`ranchu`), `ro.kernel.qemu`, telephony IDs, sensors or QEMU pipes. "The same pinned emulator used by the solve
oracle" means the grader computed the answer on a known environment. Since this check reads no environment, the
answer doesn't depend on one.

**Time Trial chain** (from `mobcheck24.py`, constants removed):

```python
def code():
    tok = mixSensor(scanAlibi(mixBoard(SEED)))       # scanAlibi: s2(), s2(), s1() brute-force probes,
    v = finEmu(f1(tok)) ^ K                           #   then + emulatorScore(iS2, iS3, iS1) * C
    return "ANS-" + "".join("0123456789ABCDEF"[(v >> i) & 15] for i in range(60, -1, -4))

def emulatorScore(a, b, c):                           # Java % truncates toward zero
    s = a + b + c
    return int(abs(s) % 4) * (1 if s >= 0 else -1)
```

The hand port uses explicit 64-bit masking (`mul`, `add`, `shl`, `ushr` helpers) to reproduce Java `long` overflow
and `>>>`. The interpreter and the port agreed, and the Time Trial submit was `CORRECT`.

## Time Trial & Mastery
- All timed modes were regular untimed attempts. Time Trial `uar` 32.
- Mastery: the interpreter solved all 10 APKs of the day (single, Time Trial and 8 mastery) without code changes.
  Mastery compute took 3.1 s, and the one submit was `CORRECT`.

## Lessons / gotchas
- A 2-minute independent re-implementation of the jadx output is cheap insurance against interpreter semantic bugs.
  It paid off the next day.
- jadx on Kali resolves *relative* paths against `/usr/share/jadx/bin`, so always pass absolute input and output paths.
- Prompts that mention runtime environments ("pinned emulator") still produced pure functions of the bytecode.
  Read the code before you build an emulator.
