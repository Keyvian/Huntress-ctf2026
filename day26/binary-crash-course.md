# ⚙️ Crash Course

| | |
|---|---|
| **Day** | 26 |
| **Lane** | ⚙️ Binary Reverse Engineering |
| **Challenge ID** | `binary-reverse-engineering-day-26-crash-triage` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day26_binary/b26.py`](../solvers/day26_binary/b26.py) (generated from `b25.py` by [`mk_b26.py`](../solvers/day26_binary/mk_b26.py)) |

## Prompt
> It crashed. That's the good news — the dump is a confession. Unwind the stack, find the faulting instruction, and triage what went wrong from the wreckage.

## TL;DR
Day-25 contract (300 questions) plus a 12-question `d26` unit: **one Groovy jar** with a synthetic crash
record (`crash/trace.json`) inside it. The config is the usual Base64 HCFG constant in the main class. Three
new "triage" fields read the trace: the faulting method (the first frame), whether every frame names a
method of the main class, and the main class's method count. The twin-jar pattern of Days 24–25 ended here.
All three modes passed on the first submit.

> Sources: this day's agent did not write its usual notes file. This writeup is based on the agent's final
> report in the run log and on the solver code and docstring.

## Artifact
WinZip-AES ZIP (password `infected`). New member `d26--sample.jar` (member 1 in ZIP order), containing:
- `META-INF/MANIFEST.MF` (`Main-Class: Day26VariantNNN`, "Huntress deterministic Groovy factory");
- `<Main>.class`, the primary class with 10 methods (`stageThree`, `stageTwo`, `stageOne`, `main`, …) and
  the `encodedConfig` Base64 constant;
- `<Main>$_main_closure1.class` (a Groovy closure);
- `crash/trace.json`: `{"schema":"huntress.synthetic_crash.v1","kind":"IllegalStateException","frames":["stageThree","stageTwo","stageOne"]}`.

Fields: `d26_artifact_sha256_1`, `d26_analysis_format` (`jar`),
`d26_analysis_config_{campaign,domain,mutex,url,crc32_hex}`, `d26_analysis_hcfg_version`,
`d26_analysis_xor_key_hex`, `d26_analysis_crash_fault_method`, `d26_analysis_crash_frames_match_methods`
and `d26_analysis_method_count`.

## Solution
1. **Primary class** = the manifest `Main-Class` (fallback: the class that holds the HCFG record).
2. **Config**: walk the primary class's constant pool and take the first CRC32-valid HCFG record among the
   Base64-alphabet UTF-8 constants of at least 80 characters (the
   [Day-24](../day24/binary-spot-the-difference.md) rule, restricted to one class). `config_crc32_hex` is
   the header CRC as `0x%08x`, `hcfg_version` is byte 4, `xor_key_hex` is byte 5 as `0x%02x`.
3. **Method count**: `methods_count` from the class file (`10`).
4. **Crash fields** from `crash/trace.json`:

```python
t = json.loads(jz.read(tr).decode("utf-8"))
frames = t.get("frames") or []
A["d26_analysis_crash_fault_method"] = str(frames[0])                      # "stageThree"
missing = [f for f in frames if str(f) not in set(method_names)]
A["d26_analysis_crash_frames_match_methods"] = "true" if frames and not missing else "false"
```

All 12 variants seen had the same shape; only the HCFG key, CRC and campaign changed. `javap` shows the
crash is a synthetic `IllegalStateException` thrown in `stageThree` behind the usual environment gates;
nothing about the crash mechanics is graded and nothing was executed.

`b26.py` was produced by a small generator script (`mk_b26.py`) that patches `b25.py` with the new
docstring, the `d26_fields()` function and the `set_answers` hook.

## Time Trial & Mastery
| Mode | Questions | Time used |
|---|---|---|
| single_solve | 312 | untimed, one submit |
| time_trial | 312 | 7.5 s end to end |
| mastery | 3120 (**10 sets** × 312) | 29.7 s end to end |

Contract diff before starting: 0 ids gone, 0 changed, 12 new.

## Lessons / gotchas
- The "stack unwinding" was a JSON list of frame names inside the jar. Look inside the container for side
  files before reaching for a debugger.
- "Frames match methods" means string membership in the class's method-name table; compute it from the
  class file rather than assuming `true`.
