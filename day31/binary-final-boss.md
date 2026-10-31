# ⚙️ Final Boss

| | |
|---|---|
| **Day** | 31 |
| **Lane** | ⚙️ Binary Reverse Engineering |
| **Challenge ID** | `binary-reverse-engineering-day-31-reversing-gauntlet` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day31_binary/b31.py`](../solvers/day31_binary/b31.py) · [`st0.py`](../solvers/day31_binary/st0.py) · [`qdiff.py`](../solvers/day31_binary/qdiff.py) · [`qshow.py`](../solvers/day31_binary/qshow.py) · [`peek31.py`](../solvers/day31_binary/peek31.py) · [`survey31.py`](../solvers/day31_binary/survey31.py) |

## Prompt
> The gauntlet: everything you've learned, across platforms and languages, in one campaign. Reconstruct it all, end to end, offline. No hints. Good luck.

## TL;DR
The last day had the usual shape: the Day-30 contract (420 questions) plus 14 `d31_*` questions, all from
one ELF with a new **`HGAU`** record appended after its section headers. "Everything you've learned" is
literally true of the bundle: by now each attempt asks 434 questions over 31 units, and mastery asks
6,510. The Day-30 trap came back: questions name `gauntlet.config.*` and `gauntlet.trace_branch`, keys that
do not exist in the decoded JSON. The `d01`–`d30` code needed no changes, and all three modes passed on the
first submit.

## Artifact
WinZip-AES ZIP (password `infected`, 36 MB for single solve). New member `d31--sample.elf`: a ~507 KB x86-64
`ET_DYN` ELF with DWARF and a `.symtab`, not stripped, with a 1.3 KB overlay after the section-header table
that holds the record. It was only parsed, never run.

Fields:

| Field | Source |
|---|---|
| `d31_artifact_sha256_1` | SHA-256 of the member |
| `d31_analysis_format` / `d31_analysis_machine` | `elf` / `62` |
| `d31_analysis_config_{campaign,domain,mutex,url}` | decoded object's `config` |
| `d31_analysis_gauntlet_config_{campaign,domain,mutex,url}` | the same `config` object |
| `d31_analysis_gauntlet_crc32_hex` | record header CRC, `0x%08x` |
| `d31_analysis_xor_key_hex` | header byte 5, `0x%02x` |
| `d31_analysis_gauntlet_trace_branch` | decoded object's `trace.branch` |

## Solution
1. `st0.py` saves `op=status` for every mode before any `start`; `qdiff.py` against the Day-30 contract
   showed 420 → 434 ids, 0 gone, 0 changed, 14 new (time trial identical); `qshow.py <json> '^d31'` prints
   the new question texts.
2. `HGAU` uses the same 12-byte header as HCFG (version +4, XOR key +5, u16le length +6, CRC32 +8, payload
   +12). Scan backward from the end of the member and keep the unique CRC32-valid record. In the sample it
   is at offset 505640, version 1, key `0xa1`. `b31.py` reuses Day 30's `hgrf_scan_back`, now with the magic
   as a parameter.
3. The decoded JSON's top-level keys are `schema` (`huntress.binary.reversing_gauntlet.v1`), `day`,
   `variant`, `languages` (31 entries), `capabilities`, `prior_anchors` (SHA-256 values from Days 29 and 30;
   not asked), `config` and `trace`. There is **no `gauntlet` key and no `trace_branch` key**: "gauntlet" is
   the object itself, and the branch is `obj["trace"]["branch"]`. `d31_fields` accepts both shapes and flags
   an unknown branch token in its diagnostics instead of submitting it silently.
4. `survey31.py` over all 17 members seen (single, time trial, 15 mastery sets) found exactly one `HGAU`
   candidate, always valid, always at 505640, and an identical `trace` everywhere (`branch: success`,
   `event_count: 73`). The vocabulary also allows `decoy` and `failure`; no variant used them. Answering
   `success` as a constant would have worked here, but the solver reads the field.

## Time Trial & Mastery
Both timed modes were regular untimed attempts (`run_for_time` not set); no rate limiting.

| Mode | Questions | Notes |
|---|---|---|
| single_solve | 434 | 434/434 computed in 1.6 s, answers reviewed with `--show '^d31'`, one submit |
| time_trial | 434 | `deadline: None`, 171 unique attempts; same flow from a saved artifact |
| mastery | 6510 (**15 sets** × 434) | one delivery per set (default + `delivery=1..14`, ~17 MB each); fetch 12 s, compute 22.7 s, submit 16.5 s |

## Lessons / gotchas
- The daily block shape held to the end: run the contract diff, expect one new `dNN_*` unit, and expect a
  prompt that promises more than the questions ask.
- A question's dotted path can name a concept (`gauntlet.trace_branch`), not a JSON key. Handle both and
  print the answers before submitting.
- Truncating log lines can mislead: `cut -c1-200` on the start line turned `n_aids 6510` into `n_aids 6`,
  which looked like a broken start.
