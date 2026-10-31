# 📱 Deep Link Drift

| | |
|---|---|
| **Day** | 02 |
| **Lane** | 📱 Mobile Android |
| **Challenge ID** | `mobile-android-day-02-deep-link-drift` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/sm.py`](../solvers/sm.py) |

## Prompt
> Day 1 taught you the roads. Now learn which ones are actually guarded — tell verified routing apart from a scheme and host that wave everybody through.

## TL;DR
The container is the same as [Day 1](../day01/mobile-exported-trust.md): a ~12 KB APK whose
`assets/huntress_puzzle.json` holds the answer. The new codec is `reverse`. Reversing the `data` string turns
`…-SNA` into `ANS-…`. Nothing in the manifest needs to be parsed.

## Artifact
- The APK has the same layout and question shape as Day 1 (`answer`, `pattern` `ANS-` + 16 uppercase hex, `exact`).
- The puzzle is `{"schema":…,"day":2,"codec":"reverse","data":"<16 hex>-SNA"}`.
- Mastery: `set1.answer` … `set3.answer`, one APK per set.

## Solution
**Theme.** Android deep links come in two kinds. A *verified* App Link uses `android:autoVerify="true"` on an
`https` scheme and host whose `/.well-known/assetlinks.json` names the app's signing certificate. A plain
custom-scheme filter, or an unverified http filter, lets any app or web page route an Intent into the Activity.
That second kind is the "scheme and host that wave everybody through."

**Extraction.** The grader only needs the decoded puzzle value:

```python
if codec == "reverse":
    answer = data[::-1]          # "…A7-SNA"  ->  "ANS-7A…"
```

`sm.py` was already the Day-1 solver with every simple codec in place. Day 2 only exercised the `reverse` branch.

## Time Trial & Mastery
- Each mode ran in one process (`start` → fetch → decode → submit). Time Trial and Mastery generate fresh case IDs
  and values, so the answer always comes from the bytes just downloaded.
- Mastery: 3 sets. Each question's artifact label says `delivery N`, and the solver fetches API delivery `N-1`
  (`delivery=3` is `invalid_delivery`).

## Lessons / gotchas
- The deep-link analysis is optional reading. The answer is in the asset JSON.
- From here on, keep a single decoder that dispatches on `codec`. Later days only add branches to it.
