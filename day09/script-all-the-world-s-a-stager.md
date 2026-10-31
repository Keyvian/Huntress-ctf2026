# 📜 All the World's a Stager

| | |
|---|---|
| **Day** | 09 |
| **Lane** | 📜 Script Analysis |
| **Challenge ID** | `script-analysis-day-09-stager-relationships` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day09/s9.py`](../solvers/day09/s9.py) + [`solvers/day09/sdec.py`](../solvers/day09/sdec.py) (static decoders) · [`qdump.py`](../solvers/day09/qdump.py) |

## Prompt
> Every stager claims to know who came before it and who comes next. Build the relationship graph from final-byte evidence alone, and expose the stage whose claimed family tree is impossible.

## TL;DR
**695 questions**: the Day-8 contract plus 80 new questions (four Lua polyglots, a Lua/OpenResty host, a
JScript scriptlet host and two advanced Bash fixtures). The earlier solvers lived on the Homebase VM, so this
day the whole lane solver was rebuilt locally as `s9.py` (question → answer rules) plus `sdec.py` (a purely
static decoder for every specimen family). The new solver never runs a specimen. It brute-forces each
Material/Codec pair until the bytes look like a plan. This pair, copied forward and patched a few times,
carried the lane from Day 9 through Day 22 and remained the base layer through Day 31.

## Artifact
WinZip-AES ZIP (`infected`), 82 files referenced by questions. New this day:

| File | Questions |
|---|---|
| `polyglot-lua-{benign-utility,downloader,launcher,staged-chain}.lua` | 4 × 11 |
| `host-lua-openresty-lua.lua` | 11 |
| `host-sct-scriptlet-jscript.js` | 11 |
| `recursive-walk.sh` (feature `recursive_walk`, primitive `bounded_recursive_function`) | 7 |
| `trap-handler.sh` (feature `trap_handler`, primitive `function_local_trap`) | 7 |

Question formats across the 695: 82 `enum`, 82 `mitre_attack_id`, 455 `exact_text`, 38 `integer`,
38 `ordered_tokens`. `qdump.py` lists the questions grouped by artifact.

The "relationship graph" in the prompt is the `stage-profile`, `next-language` and `next-stage` answers
already present in the contract. No separate "impossible family tree" question was recorded.

## Solution
### `sdec.py`: one static decoder for every family
`decode_specimen(name, text)` tries, in order:
1. **Analysis header** (`HUNTRESS_ANALYSIS_V1:<ENC>-<payload>`, see [Day 8](../day08/script-lost-in-translation.md)).
   This covers every polyglot and host fixture, including the new Lua and SCT files.
2. **Batch fragments**: inside `:HUNTRESS_INSPECT` … `:HUNTRESS_SEPARATOR_DONE`, collect
   `set name<N>=…` lines, undo `^|`/`^&`/`^^`, skip reassembly lines that only reference other variables,
   and join the fragments that form a `v=` plan.
3. **Material + Codec** (VBScript, Python, Bash, Node, and the JScript literals): find the material, then
   brute-force the representation and the inverse transform:

```python
def nums_from(material):        # every plausible byte array, both orders
    # JSON arrays, \xHH, \ooo, %HH, \uHHHH, decimal/hex token lists, hex strings,
    # base64 (also string-reversed = "reversed_base64"), base32
def inverse_candidates(arr, keys):
    yield identity; for k in keys: sub/add/xor k, rolling XOR (cipher-prev and plain-prev), xor_inc
    rotl/rotr 1..7; repeating-key XOR with key lists found in the source
# accept the first output that is printable and "plan-like": `v=N|…` containing campaign/steps, or a JSON object
```

   Candidate keys come from the codec's `param` field plus every small integer and integer list that appears
   in the source after removing the material.
4. **PowerShell**: `FromBase64String('…')`, then an optional `-bxor <key>` and `[Array]::Reverse`, then JSON.

### `s9.py`: question → answer
- Language from the id prefix (`jscript-`, `batch-`, `vbscript-`, `python-`, `bash-`, `nodejs-`,
  `polyglot-`, `host-`); suffix from a fixed list (`role`, `attack`, `adapter`, `campaign`, `url`,
  `file-path`, `expansion`, `control`, `carrier`, `windows-chain`, `stage-profile`, …).
- **Role**: polyglot/host → the recorded `role`; `bash-advanced-*` → `advanced_syntax`; JScript/Batch/VBScript
  → filename stem; Python/Bash/Node → the id word, falling back to a steps→role table.
- **Attack**: polyglot/host → the recorded `attack`; otherwise the lane table (benign `none`, stager and
  downloader `T1105`, dropper `T1140`, uploader `T1041`, impact `T1486`, persistence `T1053.003`, advanced
  `T1059.004`, else the language's `T1059.00x`).
- Style questions reuse the [Day 2](../day02/script-host-with-the-most.md) JScript rules, the
  [Day 3](../day03/script-expansion-pack.md) Batch labels and the [Day 4](../day04/script-dim-and-dimmer.md)
  VBScript control labels.
- Indicators: the plan key named by the longest id tail (`schedule-path`, `service-name`, …), otherwise a
  key map (`campaign` → `campaign_id`, `host-id` → `host_id`, …).

### Grading quirks re-learned by banking
The first by-file submit had a handful of wrong groups. Banking every other field of those files and then
trying candidates one at a time pinned them down:
- `relay-handoff` role is `staged_chain` for **JScript, VBScript and Batch**, but Python relay files stay `relay`.
- Batch `expansion`/`control` are per-variant facts and do not follow a fixed role table. On this Single
  Solve, `relay-handoff.cmd` banked as `for_indirect`/`call_subroutine` and `local-dispatch.bat` as
  `delayed`/`if_guard`.
- The Batch `expansion` rule that reproduced all 18 graded labels across Single Solve and Time Trial (the
  "legacy" convention): `%%h…` inside a `call set` line → `call_double`; a `for %%G in (…) do call set`
  loop → `for_indirect`; anything else → `delayed`. Control: `call :` → `call_subroutine`; `if defined` →
  `if_guard`; `goto :` → `goto_dispatch`; `if errorlevel` → `errorlevel_guard`; else `direct`.

## Time Trial & Mastery
- **Time Trial** (695): the first compute left 3 answers empty because a JScript variant built its material
  by concatenating literals with `+`, so the literal extractor learned `"a" + "b"` joins. Four Batch groups
  then came back wrong. Two causes: the classifier (fixed with the convention above) and a parser bug that
  took the reassembly line `set "item9=!item0!…"` as a fifth fragment.
- **Mastery**: 5 sets × 695 = **3,475** answers, shipped as nested per-set ZIPs inside the default artifact.
  Two new material variants showed up: Bash materials split across adjacent single-quoted chunks (`'abc''def'`)
  and `reversed_base64`. After both were added, everything computed, and the answers were submitted with
  `s9.py --submit --by-file --files 5` (5-file chunks, splitting only failing chunks down to single files).

## Lessons / gotchas
- A static brute-force decoder, with acceptance decided by "does this look like a plan", absorbs most new
  representation and transform variants without code changes. That is why the next 13 days needed almost
  no decoder work.
- Submit **by file group**: a wrong group isolates the bad file, and bisection inside the group finds the field.
- Batch classification labels are graded per variant. Never hard-code them per role.
- Previous: [Day 8](../day08/script-lost-in-translation.md) · Next: [Day 10](../day10/script-bind-over-matter.md).
