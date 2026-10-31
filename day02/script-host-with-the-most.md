# 📜 Host With the Most

| | |
|---|---|
| **Day** | 02 |
| **Lane** | 📜 Script Analysis |
| **Challenge ID** | `script-analysis-day-02-encoded-intent` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/solve_hostmost.py`](../solvers/solve_hostmost.py) |

## Prompt
> Windows Script Host has JScript plans for execution, download, upload, and impact. Carry your PowerShell findings forward, tell a function call from an invocation or a property access, and work out which script hands off to which.

## TL;DR
Day 1's three PowerShell scripts plus nine Windows Script Host JScript specimens (about 87 questions). Each
`.js` rebuilds a JSON "plan" at run time with an `inspect_<hex>()` function that calls `recover_<hex>()`.
Instead of re-implementing every per-file decoder, the solver evaluated only that inert reconstruction
function in an isolated Node context with the WSH host objects stubbed, then parsed the source text for three
syntax-style questions.

## Artifact
WinZip-AES ZIP (`infected`). Contents: the three Day-1 `.ps1` files (unchanged questions, see
[Day 1](../day01/script-power-play.md)) and nine JScript files whose names encode their role:

| File | Role answer |
|---|---|
| `host-context.js` | `benign_utility` |
| `memory-stage.js` | `stager` |
| `embedded-write.js` | `dropper` |
| `remote-write.js` | `downloader` |
| `outbound-transfer.js` | `uploader` |
| `local-dispatch.js` | `launcher` |
| `impact-plan.js` | `impact` |
| `staged-handoff.js` | `staged_chain` |
| `relay-handoff.js` | `staged_chain` (not `relay`) |

Each JScript file has 8 questions: `role`, `attack`, `adapter`, `campaign`, one role-specific indicator
(url, path, host, next-stage, extension, note, …), `function-style`, `invocation-style`, `property-style`.
Answer IDs look like `jscript-dropper-property-style`.

## Solution
**Plan recovery.** Each specimen defines `inspect_<hex>` (a function declaration or a `var x = function…`
expression) that calls `recover_<hex>()` and `eval`s the result into a plan
`{steps, adapter, values:{campaign_id, url, file_path, host_id, next_stage, extension, note_name, …}, stageCount}`.
The per-file decoders vary (XOR, reversal, Base64, hex, `%`-escapes), so the reliable route was to run only
`inspect_<hex>()` inside `vm.createContext({})` (with `WScript`/`ActiveXObject` replaced by inert stubs and a
short timeout) and print the returned JSON. All files of a set go through one Node call to save time under
the timer.

**Syntax styles** are read from the text of the `inspect_<hex>` body:

| Question | Values | Rule |
|---|---|---|
| function-style | `declaration`, `named_expression`, `anonymous_expression` | `function inspect_x(` vs `inspect_x = function name(` vs `inspect_x = function(` |
| invocation-style | `direct`, `call`, `apply` | `recover_x(…)` vs `recover_x.call(` vs `recover_x.apply(` |
| property-style | `dot`, `bracket_literal`, `mixed` | how the `eval`'d descriptor is read: `d.steps` vs `d["steps"]` vs both |

```python
def invoke_style(body):
    if re.search(r"recover_[0-9a-fA-F]+\s*\.\s*apply\s*\(", body): return "apply"
    if re.search(r"recover_[0-9a-fA-F]+\s*\.\s*call\s*\(", body):  return "call"
    if re.search(r"recover_[0-9a-fA-F]+\s*\(", body):              return "direct"
```

**ATT&CK per JScript role** (learned with partial-feedback banking on Single Solve):

| Role | Technique |
|---|---|
| benign_utility | `none` |
| stager, downloader | `T1105` (Ingress Tool Transfer) |
| dropper | `T1140` (Deobfuscate/Decode Files) |
| uploader | `T1041` (Exfiltration Over C2 Channel) |
| impact | `T1486` |
| launcher, staged_chain, relay | `T1059.007` (JavaScript); the language's execution technique, not a LOLBin sub-technique |

`adapter` and the indicators come straight from the recovered plan (`campaign` = `values.campaign_id`).

## Time Trial & Mastery
- Same contract on a fresh variant; the solver runs start → fetch → Node batch decode → submit in one process.
- Mastery has two sets. In this run set 1 came from the default delivery (`delivery=0`) and set 2 from
  `delivery=1`. Filenames repeat across sets, so sets were de-duplicated by **content** (the campaign ID),
  never by filename.

## Lessons / gotchas
- When a specimen ships its own decoder, evaluating just that pure function in a sandbox with stubbed host
  objects beats re-implementing a dozen decoders. From Day 9 on, the lane's solver replaced this with a fully
  static decoder (see [Day 9](../day09/script-all-the-world-s-a-stager.md)).
- `relay-handoff` is graded as `staged_chain` for JScript (and later Batch/VBScript), even though the role
  enum also lists `relay`.
- The execution-technique sub-ID depends on the language. This becomes a per-language table:
  JScript `.007`, Batch `.003`, VBScript `.005`, Python `.006`, Bash `.004`.
- Previous: [Day 1](../day01/script-power-play.md) · Next: [Day 3](../day03/script-expansion-pack.md).
