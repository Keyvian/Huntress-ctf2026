# ⚙️ Routine Check

| | |
|---|---|
| **Day** | 07 |
| **Lane** | ⚙️ Binary Reverse Engineering |
| **Challenge ID** | `binary-reverse-engineering-day-07-kotlin-staging-logic` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | Day-7 solver not preserved; the `d07` logic lives in [`solvers/day09/b9.py`](../solvers/day09/b9.py) (jar handler, top-level class first) |

## Prompt
> Kotlin coroutines don't run — they suspend, resume, and hop between states. Reconstruct the state machine from the metadata and figure out what this one was staging.

## TL;DR
Day-6 bundle plus `d07`, a **5.1 MB Kotlin jar** (the app plus the whole Kotlin standard library, 3,267
members). The config is the same Base64-wrapped HCFG constant as the Java unit, but in a top-level
`Day07Variant000.class`. The analysis itself was trivial; the real problem was speed, because scanning
thousands of stdlib classes and submitting too many parallel jobs blew the short timed windows.

## Artifact
WinZip-AES ZIP (password `infected`), units `d01`–`d06` plus `d07--variant-000.jar`. 56 answer ids
(seven units × eight); `d07` has the same fields as `d06` (SHA-256, `format` = `jar`, HCFG config fields,
`hcfg_version`).

The main class `Day07Variant000` is a Kotlin `object` (an `INSTANCE` field) with a `CONFIG` string and
seven methods: `<init>`, `decodeConfig`, `campaign`, `evaluate`, `staged` (a `suspend` function: it takes a
`kotlin.coroutines.Continuation` parameter), `main` and `<clinit>`. The coroutine "state machine" from the
prompt shows up as compiled continuation classes with `invokeSuspend` methods; no question asks about it
on this day.

## Solution
Same decode as [Day 6](../day06/binary-pool-party.md): find the `SENG…` Base64 constant, decode the HCFG
record, read `campaign` / `domain` / `mutex` / `url`, the CRC32 of the decoded JSON and the version byte.

The speed-up that mattered: do not parse 3,267 constant pools. Scan **top-level classes first** (no `/` in
the member name), then any non-`kotlin/` class, and stop at the first hit. The config class sits near the
start of the jar, so the scan ends almost immediately.

```python
top  = [zi for zi in jz.infolist() if zi.filename.endswith(".class") and "/" not in zi.filename]
rest = [zi for zi in jz.infolist() if zi.filename.endswith(".class") and "/" in zi.filename
        and not zi.filename.startswith("kotlin/")]
for zi in top + rest:
    bl += b64_hcfg(jz.read(zi))
    if bl:
        break
```

## Time Trial & Mastery
Single solve had already been completed by an earlier run against the same team identity, so this session
only had the timed modes to do.

- **Time trial**: CORRECT, but slow (about 8.3 s end to end) because of the jar scan.
- **Mastery**: 112 answers over two separate deliveries in a ranked window of about 13 seconds. Three
  problems in a row:
  1. The solver had no `start` → `retry` fallback. `start` returned the previous *expired* attempt (no
     `answer_ids`), so it fell into an untimed branch and spent 68 s submitting to a dead attempt. The fix
     was to call `retry` whenever `start` returns no live attempt.
  2. The next run took 13.7 s, just over the window. Profiling showed the decode was fine; the cost was
     **132 submit jobs at 14 workers**.
  3. Trimming every deterministic field to a single candidate (chunked) and brute-forcing only real
     enums cut it to 21 jobs. CORRECT in 8.6 s.

## Lessons / gotchas
- Big jars are mostly standard library. Skip `kotlin/` and look at top-level classes first.
- In a timed window, the number of submit requests matters more than CPU. Collapse confirmed fields into
  chunks and keep parallel singles for genuinely uncertain fields only.
- `start` can hand back an expired attempt; use `retry` (a new ranked variant) or `practice` (untimed,
  unranked) to get a live one.
- Day 17 later adds `has_coroutine_runtime` (`true`) and `method_count` (`7`, the main class's
  `methods_count`) for this unit.
