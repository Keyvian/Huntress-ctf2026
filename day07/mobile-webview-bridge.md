# 📱 WebView Bridge

| | |
|---|---|
| **Day** | 07 |
| **Lane** | 📱 Mobile Android |
| **Challenge ID** | `mobile-android-day-07-webview-bridge` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | Universal puzzle decoder (Day-5/6 lineage; the copy used that day was not preserved). The equivalent is [`solvers/day09/mob9.py`](../solvers/day09/mob9.py) |

## Prompt
> Cross a challenge-owned WebView bridge through an untrusted origin.

## TL;DR
All three modes were already solved when the Day-7 interactive session started (14:48 UTC status check: 3/3).
They were solved earlier that day against the same identity, by the universal `huntress_puzzle.json` decoder that
covered Days 1–6. **No notes from that run survive.** The artifact layout, the codec used that day and the
mastery set count were not recorded, so this writeup describes only the theme and the method that carried the lane.

## Artifact
Not recorded for this day. Every mobile artifact from Days 1–22 was a ~12 KB APK carrying
`assets/huntress_puzzle.json` (see [Day 5](../day05/mobile-backup-spill.md) for the member list). Nothing suggests
Day 7 was different, but the specific codec was not logged.

## Solution
**Theme.** `WebView.addJavascriptInterface(obj, "Bridge")` exposes the `@JavascriptInterface` methods of a Java object
to *every* page the WebView loads. If the app ever navigates to an untrusted origin (an open redirect, an
attacker-controlled deep-link URL, mixed content, or `file://` with universal access), that page can call the bridge
directly. The fix is to check origins in `shouldOverrideUrlLoading`, keep the bridge off pages the app doesn't
own, or use `WebViewCompat.addWebMessageListener` with an allowed-origin rule set.

**Extraction.** As on every v1 day: open the APK as a ZIP, read `assets/huntress_puzzle.json`, decode `data`
according to `codec`, and check the result against `ANS-[0-9A-F]{16}` before submitting.

## Time Trial & Mastery
- In the final catalog, Day 7 is the first mobile challenge whose Time Trial and Mastery have
  `run_for_time_supported: true` (Time Trial 50 s, Mastery 3 sets / 110 s ranked budgets).
- No mode-specific differences were recorded.

## Lessons / gotchas
- This is the only mobile day without a surviving decode record. The lane page and the Day 8/9 writeups show the
  decoder that was in use around this date.
