# 📱 Mobile Android — lane overview

Each mobile challenge is themed around one Android security topic: exported components, deep links, PendingIntents,
backups, providers, WebViews, TLS trust, local storage, Keystore, crypto, JNI, obfuscation, reflection, dynamic
loading, anti-debug/root/emulator checks, attestation, split APKs, protocols, white-box crypto and layered
protectors. Every challenge ships a small, inert, challenge-generated APK and asks for one value per set: the
"backend answer code" for a named case, always `ANS-` followed by 16 uppercase hex digits (`pattern`, `exact`
normalization). The question names the case and package (*"For case MOB-NN-… in package
com.huntress.mobile.dNN.v…: <prompt>. Submit only the exact backend answer code returned for this case."*).

All 31 mobile challenges were solved in all three modes (93/93). Nothing from any APK was ever installed or
executed. Days 1–22 were answered by decoding a JSON asset. Days 23–31 were mostly answered by *interpreting* the
app's Dalvik bytecode in a pure-Python VM.

## Challenges

| Day | Challenge | What it added |
|---|---|---|
| 01 | [📱 Exported Trust](../day01/mobile-exported-trust.md) | The container: `assets/huntress_puzzle.json` `{schema, day, codec, data}`; codec `plain`; 0-based deliveries |
| 02 | [📱 Deep Link Drift](../day02/mobile-deep-link-drift.md) | codec `reverse` (`…-SNA` → `ANS-…`) |
| 03 | [📱 Intent Injection](../day03/mobile-intent-injection.md) | codec `base64` |
| 04 | [📱 Pending Intent Relay](../day04/mobile-pending-intent-relay.md) | codec `xor` + `key` (base64, then XOR) |
| 05 | [📱 Backup Spill](../day05/mobile-backup-spill.md) | codec `split`: `parts` + `order`, slot `order[i]` gets `parts[i]` |
| 06 | [📱 Provider Paths](../day06/mobile-provider-paths.md) | codec `hex` |
| 07 | [📱 WebView Bridge](../day07/mobile-webview-bridge.md) | Solved by an earlier run; codec not recorded (thin source) |
| 08 | [📱 Cleartext Session](../day08/mobile-cleartext-session.md) | Mastery grows to 5 sets; `training_rotation_invalid` start glitch |
| 09 | [📱 Trust Everyone](../day09/mobile-trust-everyone.md) | Universal solver `mob9.py` (nested ZIPs, delivery fallback, pattern gate); first fully autonomous day |
| 10 | [📱 Network Config Split](../day10/mobile-network-config-split.md) | NSC XML in the APK (story only); `split` again; first parallel-agent run |
| 11 | [📱 Local Secrets](../day11/mobile-local-secrets.md) | `xor` key 81; forgiving key parser; GM rate-limit backoff |
| 12 | [📱 SQLite Assumptions](../day12/mobile-sqlite-assumptions.md) | `hex`, no code change |
| 13 | [📱 Keystore Misuse](../day13/mobile-keystore-misuse.md) | `base64`; GM guidance introduces the `run_for_time` opt-in (mobile still timed: 50 s / 110 s) |
| 14 | [📱 Predictable Crypto](../day14/mobile-predictable-crypto.md) | codec `caesar` on the printable-ASCII ring 32..126 |
| 15 | [📱 Native Library Secrets](../day15/mobile-native-library-secrets.md) | codec `native`: `.symtab` OBJECT `arena_value` in `lib/x86_64/libarena.so` |
| 16 | [📱 JNI Boundary](../day16/mobile-jni-boundary.md) | Same as Day 15; timed modes come up untimed (`deadline: None`) |
| 17 | [📱 Name Collapse](../day17/mobile-name-collapse.md) | codec `indexed`: character scatter `out[order[i]] = data[i]` |
| 18 | [📱 Encrypted Strings](../day18/mobile-encrypted-strings.md) | `xor` key 20 |
| 19 | [📱 Reflection Maze](../day19/mobile-reflection-maze.md) | codec `reflection` with `data` already plain; pattern check before codec dispatch |
| 20 | [📱 Loaded Later](../day20/mobile-loaded-later.md) | codec `dynamic`: `ANSWER` static string of the secondary `assets/payload.dex` |
| 21 | [📱 Debug Me If You Can](../day21/mobile-debug-me-if-you-can.md) | `reverse`; morning agent died mid-lane, manual resume |
| 22 | [📱 Root of Trust](../day22/mobile-root-of-trust.md) | `base64`; last all-v1 day before code analysis; mastery 6 sets |
| 23 | [📱 Hook Line and Signal](../day23/mobile-hook-line-and-signal.md) | **Schema v2 `analysis`**: compute `Release.code()`; `dalvik.py` interpreter + `native.py` (Unicorn JNI) |
| 24 | [📱 Emulator Alibi](../day24/mobile-emulator-alibi.md) | v1 `split` single; v2 `emulatorScore`; first independent hand port |
| 25 | [📱 Integrity Signals](../day25/mobile-integrity-signals.md) | `java.lang.reflect` model; `null` = `const/4 0` bug caught by cross-check |
| 26 | [📱 Split Decision](../day26/mobile-split-decision.md) | `.apks` bundles; feature-split parts; `splitSourceDirs`/`ZipFile`/stream model |
| 27 | [📱 Dependency Surface](../day27/mobile-dependency-surface.md) | All-v1 day; 11-set mastery spanning every v1 codec |
| 28 | [📱 Protocol Reconstruction](../day28/mobile-protocol-reconstruction.md) | codec `packet`: `"HA"` + len + payload + XOR checksum; package ↔ delivery check |
| 29 | [📱 White Box Key Recovery](../day29/mobile-white-box-key-recovery.md) | codec `table` (no encoder; inferred `(c - key - 3i) mod 256`); jadx `shl-long` trap |
| 30 | [📱 Layered Protections](../day30/mobile-layered-protections.md) | codec `layered` (inferred XOR `(key+i)` then reverse); v2 peel stack |
| 31 | [📱 Mobile Arena Gauntlet](../day31/mobile-mobile-arena-gauntlet.md) | All v2; 15-set mastery; `InMemoryDexClassLoader` model |

## How the lane evolved

**Phase 1, the asset puzzle (Days 1–22).** Every APK had the same skeleton (~12.7 KB): a binary
`AndroidManifest.xml`, a 2.5–2.6 KB `classes.dex`, `assets/huntress_puzzle.json` (~100 bytes) and a v1 JAR signature
(`META-INF/FIXTURE-.SF/.RSA`, `MANIFEST.MF`), plus an APK Signing Block. The dex always carried the same story pieces:
a `MainActivity` banner ("Case reference: MOB-NN-… Analyze the public APK and cross the … boundary"), a theme class
with `CODEC`/`CONTROL` constants (`"DAY-05:backup_store:…"`, `"DAY-16:jni_length:…"`), and a `ChallengeActivity` that
reads `answer`/`case_id` from extras or deep-link query parameters and loads
`http://127.0.0.1:19090/mobile/attempt/<id>/evidence?case_id=…&client_secret=SECRET-…&proof=…` in a WebView. That
backend and its `client_secret` were **always a decoy**. The value lives in the puzzle asset, decoded by `codec`:

| Codec | Day | Rule |
|---|---|---|
| `plain` | 1 | `data` |
| `reverse` | 2 | `data[::-1]` |
| `base64` / `base64url` | 3 | pad and decode |
| `xor` | 4 | base64 → XOR every byte with `key` (int; repeating if longer) |
| `split` | 5 | slot `order[i]` gets `parts[i]` (gather reading as fallback) |
| `hex` | 6 | `bytes.fromhex` |
| `caesar` | 14 | `chr((ord(c) - 32 - key) % 95 + 32)` |
| `native` | 15 | `.symtab` OBJECT `arena_value` string in the challenge-owned `.so` |
| `indexed` | 17 | `out[order[i]] = data[i]` per character, extra chars dropped |
| `reflection` | 19 | `data` already plain |
| `dynamic` | 20 | `static final String ANSWER` in `assets/payload.dex` (`static_values` `encoded_array`) |
| `split` + feature splits | 26 | blank `parts[part_index]` filled from each split's `huntress_feature.json` |
| `packet` | 28 | hex frame `"HA"` \| u8 len \| payload \| u8 XOR-of-previous-bytes |
| `table` | 29 | `(c - key - 3·i) mod 256` (inferred, no encoder shipped) |
| `layered` | 30 | base64 → XOR `(key + i) & 255` → reverse (inferred) |

Each day's solver was the previous day's plus one branch (`mob9` → `mob11` → `mob14` → `mob15` → `mob17` → `mob20`),
and from Day 28 the new codecs were added by monkeypatching `mob19.dec` so the whole chain picked them up. The decoder
never trusts the codec name alone. Every branch produces candidates, and the strict `ANS-[0-9A-F]{16}` pattern picks
one. The solver refuses to submit if any set fails the pattern.

**Phase 2, compute what the app computes (Days 23–31).** From Day 23 the Time Trial and Mastery APKs (and on Day 31
every mode) carried `{"schema":"huntress.mobile.puzzle.v2","codec":"analysis","build":"<12 hex>"}` with **no data**. The
answer is `Release.code(Context)`:

```
token  = seed → mix…() → scan…() [Probe.s1/s2/s3 brute-force loops over 0..4095 → <Theme>.<signal>(a,b,c)] → mix…()
code   = "ANS-" + 16 nibbles of ( Util.fin<Theme>( Mix.f1(token) ) ^ K )
decoys = seal…() methods and K… constants that nothing calls
```

`dalvik.py` interprets that bytecode with Java `int`/`long` semantics and fails loudly on anything it doesn't model.
Each failure during a local mastery dry run became a platform model:

| Day | Failure seen locally | Model added |
|---|---|---|
| 23 | `opcode 0x23` (new-array) in a d02 build | arrays, `fill-array-data`, `aget`/`aput` |
| 23 | `System.loadLibrary` / `native nativeShare(J)` in a d15 build | `native.py`: find the `Java_…` export, run it in a Unicorn x86-64/ARM64 sandbox |
| 25 | `Class.forName` in a d19 build | `java.lang.reflect` over the dex's own methods; staticness from the code item |
| 26 | `ctx.getApplicationInfo().splitSourceDirs` | installed split set, `ZipFile`, `AssetManager`, streams, `ByteBuffer` |
| 31 | `Class.getClassLoader` in a d20 build | `InMemoryDexClassLoader` → child VM over the secondary DEX |

Mastery grew from 3 sets (Days 1–7, 10–14) to 5 (Days 8–9, 15–21), 6 (Day 22), then one more per day up to 15 (Day 31).
From Day 23 each set was a v2 rebuild of an *earlier* day's theme, so a new day could pull in an old feature the
interpreter had never seen as code.

**Mode mechanics.** Mastery sets came either as one delivery per set (labels `…_mastery_NN.apk`, API `delivery` is
0-based: set K = `delivery=K-1`, the default artifact = set 1) or nested in one ZIP. `apks_from()` / `bundles_from()`
handle both. Early timed modes were real races: ~7 s on Day 5, 50 s / 110 s on Day 13, 30 s on Day 14. From Day 16
the GM made Time Trial and Mastery "regular" untimed attempts by default (`run_for_time:true` requested a Hall of
Fame run), so every mastery could be dry-run locally before its single submit.

## Reusable techniques
- **Read the asset before the code.** For v1 puzzles the manifest and the dex are only story.
  `zipfile` + `json` + a codec table answers it.
- **Pattern-gated decoding.** Generate every plausible reading (scatter vs gather, printable vs byte ring, reverse
  before vs after) and accept only a unique full match of `ANS-[0-9A-F]{16}`. When the APK ships no encoder (Days
  29–30), enumerate a small transform family the same way and print every alternative that also matches.
- **Static DEX parsing without decompiling.** The string table + `class_def.static_values_off` gives every
  `static final String` (Day 20). Package and case names come straight from the string table, which is enough for
  set ↔ delivery checks (`mobmap29.py`).
- **Interpret, don't execute.** A ~1,000-line pure-Python Dalvik VM (`dalvik.py`) with a growing JDK/Android model,
  plus `native.py` for JNI in Unicorn with only `PT_LOAD` segments mapped (no OS, no syscalls). `vm.trace` lists called
  vs never-called methods, which separates the real chain from the decoys.
- **Independent cross-check.** For each new v2 flavor, port the jadx output to Python by hand with explicit 64-bit
  masking (`mobcheck24/25/26.py`, `check_tt29/30.py`, `check_d20set31.py`). When the two disagree, read the smali
  (`apktool d`) before trusting jadx.
- **Dry-run mastery offline.** Save `start.json` + every `artifact*.bin` (`--save`), run `--local` on all of them, and
  submit only when every set decodes and the package mapping checks out.

## Hardest moments
- **Day 23, the v2 switch.** With no `data` field, the agent had to write a Dalvik interpreter the same morning,
  then hit two new features (arrays, then a JNI method in `libarena.so`) on the first mastery dry run. The
  pattern gate refused to submit twice (`SOME INVALID - not submitting`) until both were modeled. Mastery then went
  through on the first submit.
- **Day 25, a silent interpreter bug.** The first reflection shim treated `invoke(null, …)`'s `null` (Dalvik
  `const/4 0`) as a receiver and dropped the real argument, so the reflective route returned a constant. That would
  have been an "answer-shaped" wrong submit. The independent hand port (`mobcheck25_d19.py`) disagreed and exposed it.
- **Day 29, jadx vs smali.** `1 << ((i & 7) * 8)` in jadx's Java was really `const-wide 1; shl-long`. The hand port
  was wrong and the interpreter was right. Since then, smali is the tiebreaker.
- **Day 31, a theme never seen in mastery.** The Day-20 dynamic-DEX theme appeared in mastery for the first time on
  the last day and needed a class-loader model before the 15-set submit.
- **Early operational issues.** Mastery delivery numbering is off by one (labels are 1-based, the API is 0-based,
  Day 1). Case strings regenerate per attempt, so match by position or package name, never by case ID. Day 8's
  `training_rotation_invalid` start error went away after a short wait. Day 21's morning agent died mid-lane and the
  lane was resumed manually from the GM's solved flags.
- **Gaps in the record.** Day 7 (WebView Bridge) was solved by an earlier run whose notes didn't survive, so its
  codec is unknown. The Day 5, 6 and 8 Homebase or scratch solvers (`d5mob_solve.py`, `d6mob_solve.py`, `d8mob.py`)
  weren't copied into the repo. Their logic is the same as [`solvers/day09/mob9.py`](../solvers/day09/mob9.py).
