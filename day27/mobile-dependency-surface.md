# 📱 Dependency Surface

| | |
|---|---|
| **Day** | 27 |
| **Lane** | 📱 Mobile Android |
| **Challenge ID** | `mobile-android-day-27-dependency-surface` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day27_quick/mob26.py`](../solvers/day27_quick/mob26.py) (Day-26 solver, unchanged) |

## Prompt
> Prove which generated dependency flaw is reachable from an exported mobile surface.

## TL;DR
**Every mode was a v1 puzzle** this time. After four days of v2 `analysis` Time Trials (Days 23–26), this Time Trial
was v1 `base64` like the single. The APK is tiny (2.6 KB dex, 102-byte puzzle asset), and the "dependency flaw /
exported surface" story is decorative. `mob26.py` handled all 13 APKs of the day without code changes.

## Artifact
- `dependency_surface.apk` (Single Solve) and `dependency_surface_time_trial.apk`, each v1 `base64`.
- Mastery: **11 sets** (default artifact = set 1, deliveries for sets 2–11), all v1 codecs: `plain`, `xor`,
  `caesar`, `split` (both a plain APK and a base + feature `.apks` bundle), `dynamic` (the Day-20 secondary
  `assets/payload.dex` static strings), `reverse`, `base64`.

## Solution
**Theme.** Reachability analysis for vulnerable dependencies: a library CVE only matters if attacker-controlled
input can reach the vulnerable call. Typical entry points are an exported Activity, Service, Receiver or Provider,
a deep link, or a WebView bridge. The puzzle asset is all the grader needed.

**Extraction:** the v1 dispatcher, `base64` for both single and Time Trial. Mastery used the whole decoder history
in one submit, and every branch was already in place:

| Codec | Since | Rule |
|---|---|---|
| `plain` | [Day 1](../day01/mobile-exported-trust.md) | `data` |
| `xor` | [Day 4](../day04/mobile-pending-intent-relay.md) | base64 → XOR `key` |
| `caesar` | [Day 14](../day14/mobile-predictable-crypto.md) | shift back by `key` on the 32..126 ring |
| `split` | [Day 5](../day05/mobile-backup-spill.md) / [Day 26](../day26/mobile-split-decision.md) | slot `order[i]` gets `parts[i]`, with blank parts filled from feature splits |
| `dynamic` | [Day 20](../day20/mobile-loaded-later.md) | `ANSWER` static string of the secondary DEX |
| `reverse` | [Day 2](../day02/mobile-deep-link-drift.md) | `data[::-1]` |
| `base64` | [Day 3](../day03/mobile-intent-injection.md) | `b64decode` |

## Time Trial & Mastery
- All timed modes were regular untimed attempts. Time Trial `uar` 32.
- Mastery: 11/11 in 3.5 s, `CORRECT` with one submit.

## Lessons / gotchas
- The Time Trial can fall back to a v1 puzzle. Let the generic entry point dispatch on `schema`/`codec` rather than
  assuming that a Time Trial means v2.
