# ⚙️ Nimble

| | |
|---|---|
| **Day** | 09 |
| **Lane** | ⚙️ Binary Reverse Engineering |
| **Challenge ID** | `binary-reverse-engineering-day-09-nim-generated-runtime` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day09/b9.py`](../solvers/day09/b9.py) |

## Prompt
> Nim compiles down to C, but the generated names give it away. Learn to spot Nim's runtime fingerprints hiding inside C-shaped clothing.

## TL;DR
Day-8 contract (80 questions) plus `d09`, a Nim-compiled x86-64 ELF: 90 questions, 10 per unit. The Nim
config is a Base64 `SENG…` string literal, decoded like the Swift and Java units. The one new idea is
`hcfg_offset`: the **file offset where the Base64 string starts**. This day also produced `b9.py`, the
first single solver for every unit `d01`–`d09` in any mode, and the base of every later binary solver.

## Artifact
WinZip-AES ZIP (password `infected`) with the usual `dNN--variant-NNN.*` members plus `d09--variant-000.elf`.

The Nim binary is easy to fingerprint: symbols such as `NimMainInner`, `nimNewObj`, `toNimStr`,
`nimInErrorMode__system_u4319`, and Nim's generated C file names like `@m..@snim@slib@spure@sstrutils.nim.c`.

Every question carries an `answer_format` with a `kind`. The question texts themselves were still the generic
"What is the exact analysis … value" template, so the kind was the main hint. The Day-9 question dump
shows these kinds:

| Kind | Example fields | Expected form |
|---|---|---|
| `exact_text` | sha256, format, architecture, config strings | exact value, `none` if absent |
| `json` | `section_names`, `symbols`, `compression_methods` | compact JSON array, exact order |
| `pattern` | `entry_point`, `*_crc32_hex`, `*_xor_key_hex` | lowercase hex with `0x` |
| `integer` | `hcfg_version`, `d08`/`d09` `machine`, `d08` `elf_class`, `hcfg_offset` | base-10 integer |
| `enum` | `has_symtab`, `has_cpp_typeinfo`, `has_cpp_vtable` | `true` / `false` |

The `d03_analysis_format` question had also been rewritten to describe its answer: "identify its combined
executable-container and managed-runtime format classification … one container_runtime token" (see
[Day 3](../day03/binary-table-manners.md)).

## Solution
`d09` fields: `artifact_sha256_1`, `format` (`elf`), `architecture` (`x86-64`), `machine` (`62`),
`config_{campaign,domain,mutex,url}`, `config_crc32_hex`, `hcfg_offset`.

```python
def b64_hcfg(blob):
    out = []
    for m in re.finditer(rb"SENG[A-Za-z0-9+/]{16,}={0,2}", blob):
        s = m.group(0)
        for d in hcfg_blocks(base64.b64decode(s + b"=" * (-len(s) % 4))):
            d["off"] = m.start()          # hcfg_offset = file offset of the 'S' of SENG
            out.append(d)
    return out
```

In the single-solve variant the literal sat at offset `30696`. No raw HCFG record existed in `d09`. The
solver gathers both raw and Base64 candidates and keeps the best complete config.

`b9.py` started from the Day-8 pipeline-test solver, where two formats were untested guesses. The graded
forms were:
- `d06`/`d07` `compression_methods`: numeric ZIP method ids in first-appearance order, `[0,8]` (stored,
  then deflated), not names.
- `d08` `elf_class`: `64` (bits), not `ELF64` or `2`.

Single solve started at 39/90 banked: two of the four submitted batches came back `incorrect`, and the
batches were split until the bad fields were isolated. When artifact downloads started returning non-ZIP
responses, the solver switched to the cached artifact and only called the Game Master to submit.

## Time Trial & Mastery
`b9.py` handles both: compute every set, then submit. Mastery had 5 sets; sets 2 and 4 contained **PE
variants of `d02` and `d04`**, which the format-from-magic logic answered as `pe`. Answers were submitted
in 30-answer chunks.

## Lessons / gotchas
- Read each question's `answer_format`: it says whether a value is a label, an integer or JSON.
- Offsets are file offsets in base 10. For Base64-carried configs, `hcfg_offset` points at the Base64 text,
  not at anything inside the decoded blob. Days 11 and 13 reuse this convention.
- Keep one solver that covers every unit and grows each day. `b9.py` → `b10.py` → … → `b31.py` is one
  lineage.
