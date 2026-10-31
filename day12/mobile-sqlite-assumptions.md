# 📱 SQLite Assumptions

| | |
|---|---|
| **Day** | 12 |
| **Lane** | 📱 Mobile Android |
| **Challenge ID** | `mobile-android-day-12-sqlite-assumptions` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day12_quick/mob12.py`](../solvers/day12_quick/mob12.py) (= `mob11.py`, no logic changes) |

## Prompt
> Reconstruct authorization from a synthetic SQLite cache and prove server-side impact.

## TL;DR
The APK layout is unchanged. `assets/huntress_puzzle.json` used `{"codec":"hex","data":"414e532d…"}`, and
hex-decoding gives `ANS-<16 HEX>`. The SQLite and authorization story is a decoy, and the dex was never opened.

## Artifact
- Same APK shape as Days 9–11: manifest, `classes.dex`, puzzle asset and v1 signature files.
- Mastery: 3 sets, one APK per set. In the final catalog, both timed modes have a ranked pool size of 1.

## Solution
**Theme.** The client caches roles or entitlements in a local SQLite table (`users.is_admin`, `entitlements`), and
the server trusts what the client sends back. Editing the cache gives a privilege escalation that shows up
server-side. The fix is to treat every client-held authorization value as untrusted.

**Extraction:** `bytes.fromhex(data).decode()`. This is the Day-6 codec, already in the decoder.

## Time Trial & Mastery
- No changes. Each mode passed on its first submit. Mastery's 3 APKs came from the default artifact plus
  `delivery=1,2`.

## Lessons / gotchas
- A day with no code changes is normal for this lane. The automation's job was to notice that and avoid
  over-engineering.
