# 📱 Provider Paths

| | |
|---|---|
| **Day** | 06 |
| **Lane** | 📱 Mobile Android |
| **Challenge ID** | `mobile-android-day-06-provider-paths` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | `d6mob_solve.py` on the Homebase VM (not preserved). The same decoder is in [`solvers/day09/mob9.py`](../solvers/day09/mob9.py) |

## Prompt
> Abuse an overbroad provider path and correlate its records with prior intent evidence.

## TL;DR
The APK container is unchanged. `assets/huntress_puzzle.json` uses `codec:"hex"`, and hex-decoding `data`
(`414e532d…` = `ANS-…`) gives the answer. The dex really does contain an exported `ContentProvider`, but the answer
doesn't depend on it.

## Artifact
- APK members: `AndroidManifest.xml`, `assets/huntress_puzzle.json`, `classes.dex`, and `META-INF/FIXTURE-.SF`,
  `FIXTURE-.RSA`, `MANIFEST.MF`.
- Puzzle: `{"schema":"huntress.mobile.puzzle.v1","day":6,"codec":"hex","data":"414e532d…"}` (40 hex chars = 20 bytes).
- Dex strings for the theme: `DAY-06:content_provider:exported ContentProvider path`, class `ProviderPaths` plus
  `ProviderPathsProvider extends android.content.ContentProvider`, and the banner "cross the exported ContentProvider
  path boundary".

## Solution
**Theme.** An exported `ContentProvider` with an overbroad grant (`grantUriPermissions` on `/`, a `FileProvider`
`<root-path>`, or a path-pattern check that `..` or URL-encoding can bypass) lets other apps `query()` or
`openFile()` records far outside what the author meant to share.

**Extraction:**

```python
if codec == "hex":
    answer = bytes.fromhex(data).decode()      # 20 bytes -> "ANS-<16 HEX>"
```

The day's homebase solver (`d6mob_solve.py`) was the Day-5 universal decoder with every codec so far (`plain`,
`reverse`, `base64`/`base64url`, `hex`, `rot13`, `gzip`, `xor`, `split`), pointed at the Day-6 challenge.

## Time Trial & Mastery
- Same flow as Day 5: one fast process per attempt. Mastery has 3 sets, one APK per delivery, labeled 1-based and
  fetched 0-based.
- No issues recorded. Day 6 was solved automatically by a watcher that polled for the 13:00 UTC release.

## Lessons / gotchas
- The prompt's "correlate with prior intent evidence" didn't turn into extra questions. There is still one `answer`
  per set.
