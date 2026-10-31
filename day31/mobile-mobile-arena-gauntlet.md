# 📱 Mobile Arena Gauntlet

| | |
|---|---|
| **Day** | 31 |
| **Lane** | 📱 Mobile Android |
| **Challenge ID** | `mobile-android-day-31-mobile-arena-gauntlet` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day31_quick/mob31.py`](../solvers/day31_quick/mob31.py) (+ [`dalvik.py`](../solvers/day31_quick/dalvik.py), [`native.py`](../solvers/day31_quick/native.py)) · cross-check [`check_d20set31.py`](../solvers/day31_quick/check_d20set31.py) · mapping check [`mobmap29.py`](../solvers/day31_quick/mobmap29.py) |

## Prompt
> Complete a mass-generated multi-app campaign that composes every released mobile primitive under one aggregate clock.

## TL;DR
This is the finale. Every mode was a v2 `analysis` puzzle with no new codec
(`{"schema":"huntress.mobile.puzzle.v2","day":31,"codec":"analysis","build":…}`). `dalvik.py` computed the single and
Time Trial without changes. Mastery had **15 sets**, one v2 build per historical theme. Set 10 was the
**Day-20 "Loaded Later" theme, never drawn in a mastery rotation before**. Its code loads `assets/payload.dex` with
`InMemoryDexClassLoader` and calls `share(long)` reflectively. `mob31.py` added a class-loader model that runs the
secondary DEX in a child interpreter.

## Artifact
- Single Solve `mobile_arena_gauntlet.apk` and the Time Trial: v2 builds with the Day-31 flavor
  `MobileArenaGauntlet.gauntlet` plus `gateLane…` functions, `Probe.s1/s2/s3`, and the usual `Mix.f1` → `fin*` ^ const.
- Mastery: **15 sets** (default artifact = set 1, deliveries for sets 2–15). Set 10 (the delivery after set 9)
  is package `…d20.v…`, the dynamic-DEX theme.

## Solution
**Theme.** A gauntlet that composes every earlier primitive: exported components, deep links, intents, providers,
WebViews, transport, storage, crypto, JNI, obfuscation, reflection, dynamic loading, anti-analysis, integrity, splits,
protocols and white-box tables. The analyst has to handle all of them in one pass.

**The new mastery blocker (set 10).** `Util.lateModule` does:

```java
new InMemoryDexClassLoader(ByteBuffer.wrap(Assets.read("payload.dex")), Util.class.getClassLoader())
    .loadClass(name)                                  // name derived from LoadedLater.moduleContract()
    .getDeclaredMethod("share", Long.TYPE)
    .invoke(null, Long.valueOf(j));
```

`dalvik.py` stopped on `Class.getClassLoader`. `mob31.py` patches `VM.lib_call` and `VM.reflect_invoke` with a loader
model:

```python
if cname in LOADERS:                                   # InMemoryDexClassLoader, DexClassLoader, BaseDexClassLoader...
    ld = args[0]
    if mname == "<init>" and cname == "Ldalvik/system/InMemoryDexClassLoader;":
        ld["vm"] = dalvik.VM(dalvik.Dex(_dex_bytes(args[1], self)), max_steps=self.max_steps,
                             libs=self.libs, splits=[(p, b) for p, b in self.splits.items()])
    if mname == "loadClass":
        d = "L" + str(args[1]).replace(".", "/") + ";"
        if ld.get("vm") is not None and d in ld["vm"].dex.classes:
            return ("__loaded__", ld["vm"], d)        # a loaded class = (tag, child VM, descriptor)
```

`getDeclaredMethod` on a loaded class returns a method tuple that points into the child VM, and `Method.invoke`
runs it there (the trace shows `…share[loaded]`). The secondary DEX is interpreted by the same pure-Python VM and never
executed natively. The hand port `check_d20set31.py`
(`mixModule(share(mixLater(SEED)))` → `f1` → `finLoader` ^ K) gave the same `ANS-…` as the interpreter.

That makes the lane's full v2 feature set: 64-bit arithmetic and arrays (Day 23), JNI through Unicorn (Day 23),
`java.lang.reflect` (Day 25), split APKs with `ZipFile`/stream I/O (Day 26), and now class loaders (Day 31).

## Time Trial & Mastery
- Time Trial: same interpreter path, `CORRECT`.
- Mastery: every saved APK was run locally first. That is how set 10 was found and fixed before any submit. After
  that, `mobmap29.py` matched 15/15 packages to deliveries, compute took ~5 s, and the one submit was `CORRECT`.

## Lessons / gotchas
- A mastery rotation can pull a theme it has never drawn before, even on the last day. Run every saved APK through
  the local solver before the first submit.
- Write each extension as a model of the platform API (a class loader, a `ZipFile`, `Method.invoke`), not as a
  special case for one variant. Each fix then covered the rest of that theme's variants too.
- Quick-lane mastery set counts on the final day: warmups 153, metadata 15, mobile 15.
