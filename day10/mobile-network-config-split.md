# 📱 Network Config Split

| | |
|---|---|
| **Day** | 10 |
| **Lane** | 📱 Mobile Android |
| **Challenge ID** | `mobile-android-day-10-network-config-split` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day10_quick/mob10.py`](../solvers/day10_quick/mob10.py) (byte-identical to Day 9's `mob9.py`) |

## Prompt
> Diff manifest and Network Security Config variants to locate the true transport exception.

## TL;DR
The APK now also ships `res/xml/network_security_config.xml`, which matches the story. The answer is still in
`assets/huntress_puzzle.json`, this time with the Day-5 **`split`** codec (`out[order[i]] = parts[i]`). This was the
first day run by three parallel headless agents (the `quick` group covered warmups, metadata and mobile). The agent
copied `mob9.py` as `mob10.py`, and all three modes were `CORRECT` on the first submit.

## Artifact
- APK members: `AndroidManifest.xml`, `res/xml/network_security_config.xml`, `classes.dex`,
  `assets/huntress_puzzle.json` (plus the v1 signature files).
- Puzzle: `{"codec":"split","parts":[…],"order":[…]}`.
- Mastery: 3 sets, one APK per set (catalog: Time Trial 50 s, Mastery 3 sets / 110 s ranked budgets).

## Solution
**Theme.** A Network Security Config can loosen transport security per domain. Examples are
`<domain-config cleartextTrafficPermitted="true">`, a `<debug-overrides>` block that accidentally applies, or
user CAs trusted only for one host. The manifest attribute (`usesCleartextTraffic`) and the NSC can disagree, and
the NSC wins on API 24+. Finding the "true transport exception" means diffing the two. The grader didn't ask for
that diff.

**Extraction.** The `split` branch of `mob9.py`, unchanged:

```python
out = [None] * len(parts)
for i, o in enumerate(order):
    out[o] = parts[i]
s = "".join(out)   # must fullmatch ANS-[0-9A-F]{16}; else try "".join(parts[o] for o in order)
```

## Time Trial & Mastery
- Same solver, same codec family. Mastery fetched one APK per set via the delivery fallback (default artifact,
  then `delivery=1..n-1`).

## Lessons / gotchas
- The extra NSC XML is a hint about the theme, not a new place to look for the answer.
- Reusing a "universal" solver as-is is the fastest path. The automation copied the previous day's solver first and
  only changed it if a local decode failed.
