# ⚙️ Out of Bounds

| | |
|---|---|
| **Day** | 25 |
| **Lane** | ⚙️ Binary Reverse Engineering |
| **Challenge ID** | `binary-reverse-engineering-day-25-synthetic-vulnerability-root-cause` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day25_binary/b25.py`](../solvers/day25_binary/b25.py) · [`qdiff.py`](../solvers/day25_binary/qdiff.py) · [`inspect25.py`](../solvers/day25_binary/inspect25.py) |

## Prompt
> Somewhere in here, the code reaches where it shouldn't. Prove the bounds error is real, trace its reachability, and compare against the corrected twin that learned its limits.

## TL;DR
Day-24 contract (288 questions) plus a 12-question `d25` unit with **exactly the Day-24 shape**: a
vulnerable/corrected pair of jars, this time compiled from **Clojure**. The Day-24 handler became a
prefix-parameterized `twin_jar_fields(d, …)` and no new parsing code was needed. The whole lane took about
2.5 minutes of wall-clock time, plus contract reading.

## Artifact
WinZip-AES ZIP (password `infected`). New members in ZIP order: `d25--sample-vulnerable.jar` (8,282 B) and
`d25--sample-corrected.jar` (8,417 B). Manifest: `Created-By: Huntress deterministic Clojure factory`,
`Main-Class: day25.vulnerable000` / `day25.corrected000`. Each jar contains `day25/<ns>.class` (the
`gen-class` stub), `<ns>__init.class` (the namespace loader, which holds the `encoded-config` Base64
constant), `<ns>$_main.class`, `<ns>$parse_frame.class` and a couple of helper function classes.

Fields (same as `d24`): `d25_artifact_sha256_{1,2}`, `d25_analysis_{corrected,vulnerable}_format`,
`d25_analysis_config_{campaign,domain,mutex,url}` (both twins must decode to byte-identical configs) and
`d25_analysis_corrected_config_{campaign,domain,mutex,url}`.

## Solution
Identical to [Day 24](../day24/binary-spot-the-difference.md): walk every classfile constant pool, take
UTF-8 constants of at least 80 Base64 characters, decode, and accept the first CRC32-valid HCFG record. The
record sits in the `__init` class as a 508–552-character literal (payload 368–401 bytes); keys differ per
variant (`0xa1` in the sample). Exactly one such constant per jar, no decoys in the 11 variants seen, and
the twins' configs were byte-identical every time.

One detail mattered: the classes live in a `day25/` subdirectory. The walker visits every `.class`
regardless of path; the old Day-6/7 "top-level classes first" shortcut would have missed them.

**The bug, for the record** (`javap`, variant 000): the vulnerable `parse-frame` is `(nth frame 4)` with no
guard, so `RT.nth(frame, 4)` throws `IndexOutOfBoundsException` on a frame shorter than five elements
(`_main` builds a four-element frame and gates the call on `HUNTRESS_TRIGGER_FAULT`). The corrected version
is `(if (< 4 (count frame)) (nth frame 4) -1)`, an `RT.count` check returning a `-1` sentinel. The program
prints a JSON trace (`clojure_bounds_root_cause_trace`, `bounded_synthetic_fault_only`, network `none`).
Nothing was executed and nothing about the bug is graded.

## Time Trial & Mastery
Workflow used for every day from here on:
1. `op=status` on the base id before `start` returns the full contract; save it.
2. `qdiff.py <previous start.json> <status.json>` lists ids that are gone, new or reworded (here: 0 gone,
   0 changed, 12 new).
3. Write the delta, compute single solve offline from the saved artifact, submit.
4. Run time trial and mastery each as one live process.

| Mode | Questions | Time used |
|---|---|---|
| single_solve | 300 | untimed, one submit |
| time_trial | 300 | 5.1 s end to end (gather 4.1 s) |
| mastery | 2700 (**9 sets** × 300) | 24.3 s end to end (gather 20.7 s) |

Both timed modes came up with `deadline: null` and `run_for_time: false`.

## Lessons / gotchas
- Generalize a handler as soon as a second unit shares its shape (`twin_jar_fields("d25", …)`).
- Do not keep path shortcuts from earlier days; walk every class file.
- Run a contract diff before touching code. It turns each new day into a known, small delta.
