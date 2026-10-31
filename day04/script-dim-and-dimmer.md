# 📜 Dim and Dimmer

| | |
|---|---|
| **Day** | 04 |
| **Lane** | 📜 Script Analysis |
| **Challenge ID** | `script-analysis-day-04-shell-contrast` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/codex_day4/dim_solve.py`](../solvers/codex_day4/dim_solve.py) · [`dim_timed.py`](../solvers/codex_day4/dim_timed.py) · base analyzer [`solvers/codex_day4_script/solve_d4.py`](../solvers/codex_day4_script/solve_d4.py) |

## Prompt
> These VBScript specimens hide their material behind character codes, reversible transforms, and winding control flow. Unwind every representation on paper, classify each behavior, and find out which stage passes the baton to which.

## TL;DR
The Day-3 set (PowerShell + JScript + Batch, 159 questions) plus nine VBScript specimens, **231 questions**.
Each `.vbs` declares `Material_<id>` and `Codec_<id>="<representation>|<transform>|<param>"`. Parse the
representation into bytes, invert the transform and you get a `v=1|…` plan. The representation and
transform names are themselves answers. As on Day 3, the blocker was an unpublished label set: the VBScript
**control** form, whose `*_once` loop-wrap labels were the last tokens to bank.

## Artifact
WinZip-AES ZIP (`infected`) with 30 specimens: the 21 carried over from
[Day 3](../day03/script-expansion-pack.md) plus `host-context.vbs`, `memory-stage.vbs`, `embedded-write.vbs`,
`remote-write.vbs`, `outbound-transfer.vbs`, `local-dispatch.vbs`, `impact-plan.vbs`, `staged-handoff.vbs`,
`relay-handoff.vbs`.

Each VBScript has 8 questions: `role`, `attack`, `adapter`, `campaign`, an indicator (`host-id`, `url`,
`file-path`, `upload-url`, `extension`, `next-stage`), `representation`, `transform`, `control`.

## Solution
### Decoding the material
```vb
Material_3f9a = "118|61|49|124|…"
Codec_3f9a    = "decimal_pipe|rolling_xor|5a"
```

| Representation | Parse |
|---|---|
| `decimal_pipe`, `decimal_dash` | decimal numbers split on `\|` or `-` |
| `reversed_decimal` | decimal list, then reverse the byte order |
| `hex_compact` | hex string |
| `hex_colon` | `aa:bb:cc` |

Later days added `base64_chunks`, `decimal_csv`, `reversed_hex` and `hex_dash`.

| Transform | Inverse (param = hex key) |
|---|---|
| `subtract_modulo_256` | add the key mod 256 |
| `single_byte_xor` | XOR every byte with the key |
| `repeating_key_xor` | XOR with the comma-separated key cycled |
| `rolling_xor` | byte 0 XOR key; byte *i* XOR **previous ciphertext byte** |
| `reverse_bytes` | reverse the array |

Later days added `add_modulo_256`, `reverse_then_xor` and `identity`.

```python
if rep.startswith("reversed"): arr = arr[::-1]
if   xf == "subtract_modulo_256": arr = [(n + k[0]) % 256 for n in arr]
elif xf == "single_byte_xor":     arr = [n ^ k[0] for n in arr]
elif xf == "repeating_key_xor":   arr = [n ^ k[i % len(k)] for i, n in enumerate(arr)]
elif xf == "rolling_xor":         arr = [n ^ (k[0] if i == 0 else arr[i-1]) for i, n in enumerate(arr)]
elif xf == "reverse_bytes":       arr = arr[::-1]
text = bytes(arr).decode(); assert text.startswith("v=1|")
```

`representation` and `transform` are answered with the two names from `Codec_<id>`. `adapter`, `campaign`
(`campaign_id`) and the indicator come from the decoded plan.

### VBScript ATT&CK
Same role table as the other languages, with the VBScript execution technique for the "run code" roles:
benign `none`; stager/downloader `T1105`; dropper `T1140`; uploader `T1041`; impact `T1486`;
launcher/staged_chain/relay **`T1059.005`** (Visual Basic).

### Control form (the blocker)
The question asks for the construct that wraps the `Decode_<id>()` call inside `Function Recover_<id>()`.
Validated vocabulary:

| Construct around the decode call | Label |
|---|---|
| plain inline call | `direct` |
| `Select Case … Case …` | `select_case` |
| `Do … Exit Do … Loop` (single pass) | `do_once` |
| `While … Wend` (single pass) | `while_once` |
| one-shot `For i = 0 To 0` | `for_once` |
| `On Error Resume Next` guard | `error_guard` |

Ignore decorative branches and the per-byte decode `For` loops, which every specimen has; only the wrapper
of the decode call counts. `direct`, `select_case` and `error_guard` banked early. Flat guesses for the
loop wrappers (`do_until`, `run_once_loop`, `do_exit_loop`, … in `d4_ctrl*.py`) were all rejected. The
`*_once` family follows the same `<construct>_<qualifier>` shape as Day 3's `if_guard`. Like `if_guard`, it
came from the validated vocabulary recorded by the Codex side of the team. Once it banked, Single Solve
completed at 231/231.

### Batch convention for this challenge
The grader's Batch `expansion` labels here followed a convention rather than cmd.exe semantics: `%%h`
present in the reconstruction → `call_double`; otherwise a `for` loop with `do call set` → `for_indirect`;
otherwise `delayed`.

## Time Trial & Mastery
- Same contract on randomized variants with a timer of a few seconds. `dim_timed.py` does start → download →
  analyze → one full submit in one process: Time Trial (231 answers) in about 1.8 s, Mastery
  (462 answers, `set1.*`/`set2.*`) in about 2.7 s.
- Mastery sometimes delivered **one nested ZIP holding both sets**, and sometimes the default delivery held
  only set 1. In that case fetch `delivery=1` for set 2.
- Any Batch/VBScript classification field that a variant got wrong could be brute-forced by banking, as on
  [Day 3](../day03/script-expansion-pack.md).

## Lessons / gotchas
- Rolling XOR chains on the **previous ciphertext byte** (not the previous plaintext byte). Try both if a
  decode fails.
- The codec string is a free answer: the representation and transform questions ask for those names exactly.
- The undocumented control vocabularies (Batch `if_guard`, VBScript `*_once`) share a naming shape:
  `<construct>_<qualifier>`.
- Previous: [Day 3](../day03/script-expansion-pack.md) · Next: [Day 5](../day05/script-hatch-careful.md).
