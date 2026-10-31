# 📜 Mixed Signals

| | |
|---|---|
| **Day** | 26 |
| **Lane** | 📜 Script Analysis |
| **Challenge ID** | `script-analysis-day-26-beam-message-flow` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day26_script/s23.py`](../solvers/day26_script/s23.py) (verbatim copy of Day 25) · [`lyr.py`](../solvers/day26_script/lyr.py) · [`qdiff.py`](../solvers/day26_script/qdiff.py) / [`wdiff.py`](../solvers/day26_script/wdiff.py) |

## Prompt
> An Erlang escript passes messages between processes, and some of its indicators look suspiciously familiar. Trace the message flow, and separate the true cross-language indicators from deterministic collision decoys planted to look like old friends.

## TL;DR
Four **Erlang escript** polyglots (no host file). Single Solve = Day-25 single + 44 (1,615); timed =
Day-25 timed + 52 (1,677); Mastery **10 sets** (16,770). Zero solver changes. The escripts contain no message
passing and no decoy indicators: decoding every file in both bundles showed every campaign token, URL host
and path leaf to be unique.

## Artifact
- Single Solve: `polyglot-erlang-{benign-utility,downloader,launcher,staged-chain}.escript`, 11 questions
  each, 171 files in all. Every `host-profile` answer is `standalone`.
- Time Trial / Mastery: the same four as hash-named `.escript` files, 13 questions each.

The simplest carrier of the event:

```erlang
% HUNTRESS_ANALYSIS_V1:<HEADER>-<payload>
-module(plan_<hex>).
-export([build_plan/0]).
build_plan() -> "<same payload>".
```

Single Solve headers: `HB64`, `FRAG`, `HEX`, `B64`. Timed: `LYR-<chain>` (`hex_b32_hex`, `b32_b64_b32`,
`b64_b64_rev`, `b32_hex_b32`, `hex_b64_rev`, …).

## Solution
1. **Read the contract before starting.** `op=status` on the base ID works before `start` and returns the
   question list. `qdiff.py <day25 single start.json> status0.json` → 44 new, all Erlang.
2. `fetch.py` + `extract.py` → `s23.py --dir` → 1,615/1,615, no diagnostics. Payload:
   `v=3|language=erlang|role=…|attack=…|adapter=…|host_profile=standalone|obfuscation_profile=…|…|campaign_id=ERLANG-<8hex>|url=https://erlang-<10hex>.example.invalid/stage|file_path=/tmp/huntress-erlang/.<16hex>.stage`.
3. **Checking the "collision decoys" claim.** There is no `spawn`, `!` or `receive` anywhere, just one
   `build_plan/0` returning the payload string. Across all 171 files of both the single and the Time Trial
   bundle, the 158 distinct campaign tokens, 117 URL hosts and 122–124 path leaves were all unique, so no
   Erlang indicator collides with an older language's. Every answer is a field of the decoded descriptor,
   with the recorded role/attack (e.g. `downloader` + `T1105` with steps ending in `dispatch_language`, or
   `persistence_descriptor` + `T1053`).
4. Single Solve: `--submit --by-file --only erlang` (4 × 11 `accepted`), then `--submit --exclude erlang` → CORRECT.

## Time Trial & Mastery
- Time Trial: untimed (`deadline: None`, `run_for_time: False`, 32 unique attempts).
  `wdiff <day25 tt> <day26 tt>` → only the 13 Erlang shapes new, 0 gone, 0 reworded. Bank the 4 Erlang groups
  (13 each), then submit the remaining 1,625 → CORRECT.
- Mastery: `s23.py <ch>/mastery --save <dir>`. Start took 2.3 s, all 10 sets were loaded from the default ZIP
  by 5.0 s, and 16,770 answers were computed by 6.2 s. Cached `--submit --by-file --only erlang --files 10`
  (4 groups of 130 `accepted`), then the remaining 16,250 → CORRECT.

## Lessons / gotchas
- When a prompt claims there are decoys, a quick uniqueness check over all decoded indicators settles it in
  seconds.
- `op=status` before `start` is a cheap way to diff the contract without opening an attempt.
- Previous: [Day 25](../day25/script-ashes-to-assets.md) · Next: [Day 27](../day27/script-from-whence-it-came.md).
