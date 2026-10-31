# 📱 Split Decision

| | |
|---|---|
| **Day** | 26 |
| **Lane** | 📱 Mobile Android |
| **Challenge ID** | `mobile-android-day-26-split-decision` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day26_quick/mob26.py`](../solvers/day26_quick/mob26.py) + patched [`dalvik.py`](../solvers/day26_quick/dalvik.py) (split-APK / ZipFile / stream model) · cross-check [`mobcheck26.py`](../solvers/day26_quick/mobcheck26.py) · AXML reader [`apk.py`](../solvers/day26_quick/apk.py) |

## Prompt
> Reassemble evidence distributed across base and configuration splits.

## TL;DR
The artifact is no longer a single APK. It is an **`.apks` bundle**, a ZIP holding `base.apk` and a feature split
(split name `arena_feature`, `hasCode=false`). In Single Solve the v1 **`split`** puzzle in `base.apk` has a
*blank* part, and the feature split supplies it through `assets/huntress_feature.json`. In the Time Trial v2 build,
the code itself opens the feature split through `ApplicationInfo.splitSourceDirs` and reads 16 bytes from it. So
`dalvik.py` gained a model of installed splits, `ZipFile`, `AssetManager` and Java streams.

## Artifact
- `split_decision.apks` = ZIP of `base.apk` + `feature.apk`.
- Single Solve, values changed here:
  - `base.apk` → `assets/huntress_puzzle.json` =
    `{"codec":"split","data":"","parts":["","ANS-A","BBBBBB"],"order":[2,0,1]}`
  - `feature.apk` → `assets/huntress_feature.json` = `{"codec":"split","part":"CCCCCCCCC","part_index":0}`
- Time Trial: `base.apk` v2 `analysis`. The feature split carries `assets/huntress_feature.bin` (16 bytes).
- Mastery: **10 sets**, one bundle per delivery (default = set 1, deliveries for sets 2–10). Themes: d20 deep-link,
  d21 intent injection, d22 provider, d23 prefs, d24 keystore, d15 JNI (through `native.py`), d19 reflection, d08
  debugger, d25 integrity, and d26 split (`base.apk` + `split_arena_feature.apk`).

## Solution
**Theme.** Android App Bundles install as a *split set*: `base.apk` plus configuration splits (ABI, density,
language) and feature splits. Each split has its own manifest (`split="…"`), and resources or assets can live in
any of them. An analyst who only looks at `base.apk` misses part of the evidence.

**Single Solve.** Fill `parts[part_index]` from each split's `huntress_feature.json`, then apply the
[Day-5](../day05/mobile-backup-spill.md) scatter: slot `order[i]` gets `parts[i]`. With the example above:
`out[2]="CCCCCCCCC"`, `out[0]="ANS-A"`, `out[1]="BBBBBB"`, which joins to `ANS-ABBBBBBCCCCCCCCC`. The other reading,
`parts[order[k]]`, fails the ANS pattern.

**Time Trial.** The token chain gains a split read:

```java
// Sketch of the decompiled flow (constants omitted)
// Assets.readSplit("huntress_feature.bin"):
String path = ctx.getApplicationInfo().splitSourceDirs[…];          // the installed feature split
InputStream in = new ZipFile(path).getEntry("assets/huntress_feature.bin") → getInputStream();
in.read(buf /* byte[16] */);                                        // -> hi, lo (two big-endian u64)
// Util.mergeFeature…(t):
t = (rotl(t ^ hi, 55) * C1 + lo) ^ K2;   return rotl(t, 32) * C3;
```

Instead of hand-porting each variant, the interpreter now models the platform:
- `VM(splits=[(install_name, apk_bytes), …])`. `Context.getApplicationInfo()` returns `{sourceDir,
  splitSourceDirs: ["/data/app/huntress-1/split_<name>.apk"], splitNames}`.
- `mob26.install_name()` reads each split's binary AndroidManifest `split` attribute (through `apk.axml`) to name it
  `split_<splitName>.apk`. The APK carrying the puzzle becomes `base.apk`.
- Library models: `AssetManager.open`, `ZipFile`/`ZipEntry`/`Enumeration`, `InputStream.read`/`readAllBytes`/`readFully`,
  `ByteArrayOutputStream`, `ByteBuffer` (`wrap`/`order`/`getLong`), `Arrays`, `String.getBytes`/`new String(bytes)`/
  `endsWith`/`contains`/`split`, `System.arraycopy`, the `ByteOrder`/`StandardCharsets` statics, generic dict-backed
  `new-instance` for library types, and null-safe `if-eq`/`if-ne`.

`mobcheck26.py` re-implements the jadx output by hand, reading `huntress_feature.bin` from the bundle. It matched
the interpreter, and the Time Trial was `CORRECT`.

## Time Trial & Mastery
- All timed modes were regular untimed attempts. Time Trial `uar` 32.
- Mastery: all 10 sets ran through the interpreter in 5.5 s. In set 10 the trace shows `Assets.readSplit` reading the
  feature split. Submitted once: `CORRECT`.
- `bundles_from()` treats a bare APK as a one-member bundle, an `.apks` as one bundle, and a ZIP of `.apks` as one
  bundle per inner `.apks`. One code path covers both old and new artifact shapes.

## Lessons / gotchas
- Once v2 code starts reading the `Context`, model the Android/JDK I/O APIs in the interpreter rather than
  hand-porting each variant. Keep one hand cross-check per day anyway. It agreed first time here.
- The convention for the `split` codec (slot `order[i]` gets `parts[i]`) stayed the same from Day 5 to Day 26.
