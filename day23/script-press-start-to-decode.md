# 📜 Press Start to Decode

| | |
|---|---|
| **Day** | 23 |
| **Lane** | 📜 Script Analysis |
| **Challenge ID** | `script-analysis-day-23-game-resource-loader` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day23_script/s23.py`](../solvers/day23_script/s23.py) (timed contract) · [`lyr.py`](../solvers/day23_script/lyr.py) (layered decoder) · [`sdec.py`](../solvers/day23_script/sdec.py) + [`s9.py`](../solvers/day23_script/s9.py) (base) · analysis helpers [`contract.py`](../solvers/day23_script/contract.py), [`sufmap.py`](../solvers/day23_script/sufmap.py), [`missing.py`](../solvers/day23_script/missing.py), [`wdiff.py`](../solvers/day23_script/wdiff.py), [`psplans.py`](../solvers/day23_script/psplans.py), [`rolediff.py`](../solvers/day23_script/rolediff.py), [`confirm.py`](../solvers/day23_script/confirm.py) |

## Prompt
> A GDScript resource loader builds its strings in layers, one power-up at a time. Undo the construction, recover the exact indicators, and correlate its stage relationships with the rest of the corpus to find the level that doesn't belong.

## TL;DR
Single Solve was routine: the Day-22 contract plus four **GDScript** polyglots (1,461 questions), solved by
the Day-22 solver unchanged. The timed modes broke the 14-day routine. They used a **rewritten contract**
(1,495 questions, 21 answer suffixes), and the Day-22 solver could answer only **325** of them. Four things
were new: a layered `LYR-<chain>` header encoding, composite "N labels joined by `|`" answers, derived
indicators (campaign token, URL host, path leaf, primary indicator, a cross-file handoff ID), and
hash-named PowerShell fixtures whose JSON key layout depends on the scenario. `lyr.py` plus `s23.py`
covered all of it, and Mastery (7 sets, 10,465 answers) computed in under a second.

## Artifact
- **Single Solve**: the Day-22 archive plus `polyglot-gdscript-{benign-utility,downloader,launcher,staged-chain}.gd`
  (11 questions each, headers `HEX`/`FRAG`/`B64`/`HB64`). `qdiff`: 0 gone, 0 changed, 44 new.
- **Time Trial / Mastery**: a different variant where most files are renamed to short hashes
  (`e119e7.ps1`, `4c1097.py`, `polyglot-<lang>-<6hex>.<ext>`, …), with a new set of question wordings.
  Time Trial: 1,495 questions; Mastery: 7 sets × 1,495 = 10,465, all inside one default artifact.

Nothing asked about "the level that doesn't belong". A grep of the contract for belong/corpus/outlier/unique
found nothing.

## Solution
### 1. Find out what changed (before writing code)
`contract.py`, `sufmap.py` and `missing.py` on the saved timed `start.json` produce the suffix inventory and
the exact question families the old solver left unanswered. `wdiff.py` compares question *wordings* against
Day 22's timed `start.json` (IDs are hash-based, so `qdiff` cannot be used). That proved the wordings were new.

### 2. The `LYR` layered header
`HUNTRESS_ANALYSIS_V1:LYR-<layer>_<layer>_<layer>-<payload>` lists the encodings **in the order they were
applied**, so decode **right-to-left**. Layers: `hex`, `b64`, `b32`, `rev` (string reversal), `frag` (strip
`.` separators). Specimens use 1–3 layers, and one variant contained 49 distinct chains (`hex_b32_b32`,
`b64_rev_hex`, `b32_frag_hex`, bare `b32`, …).

```python
LAYERS = {"hex": _hex, "b64": _b64, "b32": _b32, "rev": lambda s: s[::-1], "frag": _defrag}

def decode_layers(chain, payload):
    t = payload
    for name in reversed([c for c in chain.split("_") if c]):   # right-most = outermost
        t = LAYERS[name](t)
    return t
```

Strict chain order decoded every plain-header file. The `.gs` files wrap the chain inside the Day-18 `SPLIT`
array ([Day 18](../day18/script-orphan-process.md)), so `decode_analysis()` handles `LYR` on both paths.
`lyr.auto_decode()`, a chain-agnostic "peel anything that works" search, is kept as a fallback. For
polyglots, the `obfuscation` answer is the descriptor's `obfuscation_profile`, which equals the chain
exactly (e.g. `b64_hex_hex`).

### 3. Composite answers
| Suffix | Wording | Answer |
|---|---|---|
| `carrier` (Python) | "carrier profile and the Windows execution-chain profile … two labels" | `carrier\|windows_chain` |
| `obfuscation` (Python) | "syntax profile and the obfuscation profile … two labels" | `syntax\|obfuscation` |
| `style` (JScript) | "function style, invocation style, descriptor property-access style" | `declaration\|call\|dot`-style triple ([Day 2](../day02/script-host-with-the-most.md)) |
| `style` (Batch) | "behavior-graph topology, control-flow wrapper, variable-expansion form" | `graph\|control\|expansion` ([Day 15](../day15/script-crumb-trail.md)) |
| `style` (VBScript) | "descriptor representation, byte-transform family, control-flow wrapper" | `representation\|transform\|control` ([Day 4](../day04/script-dim-and-dimmer.md)) |

The existing classifiers needed no change, only re-joining with `|`. The first by-file submit showed the
breakage clearly: the Python groups came back `incorrect` (single labels where pairs were now required)
while every other language was `accepted`.

### 4. Derived indicators (all languages)
- `campaign-token`: the campaign ID after the **first** hyphen (`GDSCRIPT-<8hex>` → `<8hex>`,
  `campaign-<10hex>` → `<10hex>`, `BASHX-<8HEX>` → `<8HEX>`).
- `url-host`: `urlsplit(url).hostname`.
- `path-leaf`: the last segment of `file_path`, splitting on **both** `/` and `\` (JScript paths are
  `C:\Users\Public\…`). Keep leading dots (`.<16hex>.stage`).
- `indicator`: the first non-empty of `url, upload_url, next_stage, file_path, schedule_path, note_name, host_id`.
  Python's `target_root`/`archive_path` are not in the list.
- `handoff-id` (1 question): "the handoff id that the PowerShell precursor in this archive passes to `<F>`".
  The hash-named `.ps1` holds `$HandoffId='PSPY-…'` and `$NextStage='<hash>.py'`, and the target Python plan
  records the same `handoff_id`, so either source works.

### 5. The trap: hash-named composite PowerShell fixtures
The timed modes rename `resource-/collection-/impact-sample.ps1` to 6-hex names and ask only `url`,
`secondary` and `tertiary`. The decoded JSON keeps single-letter keys **whose meaning depends on the
scenario** ([Day 1](../day01/script-power-play.md)). The old stem-based detection silently read the
impact layout for every file. Detect the scenario from the shape of `c` instead:

| Scenario (detected by) | url | secondary | tertiary |
|---|---|---|---|
| resource hijacking (`c` = `wallet_…`) | `b` | `c` (wallet) | `h` (`Global\…` mutex) |
| collection (`c` is a list) | `b` | `c[0]` (`update-….dat`, **not** the `stage-….zip` in `d`) | `f` (user agent) |
| impact (otherwise) | `d` | `c` (`RECOVERY-….txt`) | `b` (extension such as `.locked-<5hex>`) |

The first full Mastery submit was `incorrect` because of the collection `secondary`. A value-shape scan
remains as a backstop. Note that the impact extension contains a hyphen, so `^\.[A-Za-z0-9.]+$` misses it.

### 6. Role
Several role questions now state a "terminal intent" rubric. `role_terminal()` re-derives the role from the
last step (`handoff_script` → `staged_chain`, `dispatch_next_stage` → `relay`, memory dispatch → `stager`, …).
It **agreed with the old classifier on all 134 role questions**, and the recorded descriptor `role` still
wins when present.

## Time Trial & Mastery
- Both came up untimed (`deadline: None`, regular scored play).
- Workflow: write `lyr.py` + `s23.py`, validate offline against the cached Time Trial directory (`--dir`, no
  submits), then submit by file group (12 files per batch for Time Trial, 40 for Mastery).
- Mastery: 7 sets in one default artifact; 10,465 answers computed in about 0.7 s after a 2 s gather.
- A mid-run `ConnectionResetError` from the GM killed an unguarded submit loop. `fetch.py`, `timed.py` and
  `s23.py` now catch exceptions in the retry loop and rebuild the HTTP session.

## Lessons / gotchas
- Always diff the **timed** contract too (`wdiff` on wordings, since IDs are hash-based), not just the
  Single Solve one. The two contracts can diverge without warning.
- Submitting by file group localized the failures to Python (composite labels) and PowerShell (key layout).
  A single 1,495-answer submit would only have said `incorrect`.
- From here on, `s23.py` (with `s9.py`/`sdec.py` underneath) was the lane's solver, and it ran unchanged
  through Day 31.
- Previous: [Day 22](../day22/script-next-next-finish.md) · Next: [Day 24](../day24/script-web-of-lies.md).
