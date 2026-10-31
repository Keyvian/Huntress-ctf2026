# 📜 Script Analysis — lane overview

The script lane hands you an archive of **inert** script specimens (WinZip-AES ZIP, password `infected`) and
asks hundreds, later thousands, of exact questions about them: the role of each script, its primary ATT&CK
technique, its adapter and campaign, the exact indicators, and language-specific "how was this written"
labels. Nothing is ever executed. Every specimen carries its own configuration in some encoded form, and
the work is to decode it statically and map each question to the right field.

The lane **compounds**. Each day's Single Solve contract is the previous day's contract, with the same
question IDs, plus the questions for that day's new language. It started with 15 questions on Day 1 and
ended with 1,846 on Day 31. Mastery bundles 2 to 15 independent sets of the full contract, ending at 29,250
answers in one attempt. Every mode of all 31 challenges was solved.

## Day by day

| Day | Challenge | What it added | Single / timed questions · Mastery |
|---|---|---|---|
| 01 | [Power Play](../day01/script-power-play.md) | PowerShell: Base64 JSON with single-letter keys; scenario + ATT&CK + indicators | 15 · 2 sets |
| 02 | [Host With the Most](../day02/script-host-with-the-most.md) | WSH JScript: `inspect()`→`recover()` plan reconstruction; function/invocation/property style labels | ~87 · 2 sets |
| 03 | [Expansion Pack](../day03/script-expansion-pack.md) | Batch: `set`-fragment plans; **expansion** and **control** labels; the `if_guard` wall; banking brute force for timed modes | 159 · 2 sets |
| 04 | [Dim and Dimmer](../day04/script-dim-and-dimmer.md) | VBScript: `Material`/`Codec` (representation × transform); control labels incl. `*_once` | 231 · 2 × 231 |
| 05 | [Hatch Careful](../day05/script-hatch-careful.md) | 14 Python carriers (pyc, wheel, zipapp, PyInstaller, py2exe, cx_Freeze, PyArmor, embedded); carrier/windows-chain labels; parallel timed submits | 357 · 2 × 357 |
| 06 | [Shell We Begin](../day06/script-shell-we-begin.md) | 6 Bash behavior graphs; `stage-count` and ordered `steps`; `T1059.004` | 399 · 2 × 399 |
| 07 | [Node by Node](../day07/script-node-by-node.md) | 8 Node `.mjs`; `persistence_descriptor` → `T1053.003`; first advanced-syntax Bash pair (`feature`/`primitive`) | 469 · 2 × 469 |
| 08 | [Lost in Translation](../day08/script-lost-in-translation.md) | **`HUNTRESS_ANALYSIS_V1` polyglot header** (B64/HEX/HB64/FRAG); PHP polyglots + 4 host fixtures; recorded role/attack | 615 · 5 × 615 |
| 09 | [All the World's a Stager](../day09/script-all-the-world-s-a-stager.md) | Lua + OpenResty/SCT hosts; **static rebuild of the whole solver** (`s9.py` + `sdec.py`) | 695 · 5 × 695 |
| 10 | [Bind Over Matter](../day10/script-bind-over-matter.md) | WMI MOF polyglots; `qdiff` + `timed.py`; prompt ≠ questions | 753 · 2 × 753 |
| 11 | [By Any Other Name](../day11/script-by-any-other-name.md) | TypeScript polyglots; shared-token rate-limit backoff | 811 · 2 × 811 |
| 12 | [AutoIt Takes Two](../day12/script-autoit-takes-two.md) | AutoIt polyglots; 192 questions reworded with no answer change | 855 · 2 × 855 |
| 13 | [Zip Code](../day13/script-zip-code.md) | AppleScript polyglots | 913 · 2 × 913 |
| 14 | [Trust the Process](../day14/script-trust-the-process.md) | MSBuild XML polyglots; recorded `T1059` beats per-language tables | 971 · 2 × 971 |
| 15 | [Crumb Trail](../day15/script-crumb-trail.md) | Perl + Perl CGI host; **timed modes become untimed by default**; **syntax-true Batch expansion** | 1,026 · 5 × 1,026 |
| 16 | [Same Same, But Different](../day16/script-same-same-but-different.md) | Ruby + Rack host | 1,095 · 5 × 1,095 |
| 17 | [Fetch Quest](../day17/script-fetch-quest.md) | AutoHotkey v2 polyglots | 1,139 · 5 × 1,139 |
| 18 | [Orphan Process](../day18/script-orphan-process.md) | Google Apps Script; **SPLIT** header (payload split over a string array) | 1,194 · 5 × 1,194 |
| 19 | [Sharp Practice](../day19/script-sharp-practice.md) | C# script + ASPX host embedding a `.csx` in a string literal (regex stops at `\`) | 1,249 · 5 × 1,249 |
| 20 | [The Butler Did It](../day20/script-the-butler-did-it.md) | Groovy + Jenkins host; **back-filled** classic-ASP host for an old language | 1,329 · 5 × 1,329 |
| 21 | [Actions Speak Louder](../day21/script-actions-speak-louder.md) | GitHub Actions workflow polyglots | 1,373 · 5 sets (timed details unrecorded) |
| 22 | [Next, Next, Finish](../day22/script-next-next-finish.md) | NSIS installer polyglots | 1,417 · 6 × 1,417 |
| 23 | [Press Start to Decode](../day23/script-press-start-to-decode.md) | GDScript; **rewritten timed contract**: `LYR` layered encodings, composite `a\|b` answers, derived indicators, hash-named PowerShell layouts (`s23.py`) | 1,461 / 1,495 · 7 × 1,495 |
| 24 | [Web of Lies](../day24/script-web-of-lies.md) | JSP + JSP webshell host | 1,516 / 1,560 · 8 sets |
| 25 | [Ashes to Assets](../day25/script-ashes-to-assets.md) | Elixir + Phoenix host | 1,571 / 1,625 · 9 sets |
| 26 | [Mixed Signals](../day26/script-mixed-signals.md) | Erlang escript; "collision decoys" checked and absent | 1,615 / 1,677 · 10 sets |
| 27 | [FROM Whence It Came](../day27/script-from-whence-it-came.md) | Dockerfile; Time Trial briefly reused the single IDs | 1,659 / 1,659 · 11 sets |
| 28 | [Out of Order](../day28/script-out-of-order.md) | Terraform HCL; timed contract back to hash-named IDs | 1,703 / 1,781 · 12 sets |
| 29 | [Make It Make Sense](../day29/script-make-it-make-sense.md) | Makefile | 1,747 / 1,833 · 13 sets |
| 30 | [Spill the Beans](../day30/script-spill-the-beans.md) | BeanShell + JSP/BeanShell host | 1,802 / 1,898 · 14 sets |
| 31 | [The Full Transform](../day31/script-the-full-transform.md) | XSLT; `wdiff2`, `adiff`, compute-complete gate | 1,846 / 1,950 · 15 × 1,950 = 29,250 |

## How the lane evolved

### 1. Windows script hosts and hidden vocabularies (Days 1–4)
The first four days each added one Windows scripting host, with a fixed set of nine role-named specimens
(`host-context`, `memory-stage`, `embedded-write`, `remote-write`, `outbound-transfer`, `local-dispatch`,
`impact-plan`, `staged-handoff`, `relay-handoff`). Recovering the configuration was never the hard part:
PowerShell has a Base64 literal, JScript `eval`s a plan, Batch splits it over `set` lines, and VBScript uses
`Material` + `Codec`. The hard part was **classification labels the grader never enumerated**. Batch
`expansion` and `control`, and VBScript `control`, are `exact_text` questions with no accepted values. The
answers (`call_double`, `for_indirect`, `goto_dispatch`, `errorlevel_guard`, `if_guard`, `do_once`,
`while_once`, `for_once`, `error_guard`) had to be found by banking guesses one at a time. Day 3's last two
fields resisted about 145 guesses until a second model proposed `if_guard`.

### 2. Self-describing carriers and the timed-mode arms race (Days 5–7)
Python carriers, Bash graphs and Node modules all shipped a decode routine plus a `v=1|…`/`v=2|…` plan. At
the same time, the timed modes hit their tightest point: about 7 seconds, no banking across attempts, and
hundreds of answers per attempt. The answer was a parallel submitter (chunks of about 40 answers, plus every
candidate label of each variant-dependent enum as its own single-answer submit). The real constraints turned
out to be the submit payload size limit and rate limiting, not compute time.

### 3. The polyglot era: diff, reuse, bank (Days 8–22)
Day 8 introduced `HUNTRESS_ANALYSIS_V1:<ENC>-<payload>`: one header line, in whatever comment syntax the
language uses, whose payload decodes to a `v=3|…` descriptor that **records** role, attack, adapter, host
profile, obfuscation profile, stage profile, next language, stage count, steps, campaign, URL and file
path. From then on each day added one language as four polyglots (`benign-utility`, `downloader`,
`launcher`, `staged-chain`), often a host fixture, and often two advanced-Bash fixtures. The prompts
described rich forensic tasks (WMI bindings, network evidence, process trees, CI trust boundaries) that never
became questions.

Day 9 rebuilt the solver as a fully static decoder (`sdec.py`) plus a rule table (`s9.py`). After that, a day
took a few minutes:
1. `fetch.py` (start + artifact, with backoff) and `qdiff.py <yesterday start.json> <today start.json>`;
2. run yesterday's solver with `--show <new language>`, and patch only if something is unanswered;
3. bank the new files' groups first (`--by-file --only <lang>`), then the rest in 10-file batches;
4. run `timed.py` for Time Trial and Mastery (start → fetch → compute → one full submit, falling back to
   per-file banking).

The solver only needed three patches in 14 days: the Batch expansion rule (Day 15), SPLIT arrays (Day 18),
and a backslash stop for headers inside string literals (Day 19).

### 4. Split contracts (Days 23–31)
On Day 23 the timed modes got their own contract: hash-named files, 13 questions per polyglot (adding
`url-host`, `path-leaf`, `campaign-token`), `LYR-<chain>` layered encodings decoded right-to-left, composite
"labels joined by `|`" answers for the old languages, and scenario-dependent JSON layouts for the
hash-named PowerShell fixtures. `s23.py` (on top of `s9.py`/`sdec.py`) handled it and then ran unchanged for
nine days. The daily check grew to `qdiff` on the single contract plus `wdiff` on the timed wording, which
caught the Day-27 and Day-28 flips between "timed reuses single IDs" and "timed uses hash IDs". Day 31 added
`wdiff2` (to ignore a cosmetic format-hint rewrite), `adiff` (proving that yesterday's answers must not be
reused) and a mastery driver that refuses to submit an incomplete compute.

## The solver stack (Days 9–31)

| File | Role |
|---|---|
| [`sdec.py`](../solvers/day31_script/sdec.py) | Static decoders: analysis header (B64/HEX/HB64/FRAG/URL/LYR, SPLIT arrays), Batch `set` fragments, generic Material+Codec brute force (every representation × inverse transform, accepted when the output "looks like a plan"), PowerShell Base64/XOR/reverse JSON |
| [`s9.py`](../solvers/day31_script/s9.py) | Question → answer rules: language from id prefix, suffix table, role/attack tables, JScript/Batch/VBScript style classifiers, key map; `--submit --by-file --files N --only/--exclude` with bisection |
| [`s23.py`](../solvers/day31_script/s23.py) | Day-23 timed contract on top of `s9`: composite answers, derived indicators, terminal-intent role, composite PowerShell layouts, `--save` live one-process runs |
| [`lyr.py`](../solvers/day31_script/lyr.py) | `LYR` chain decoder (strict right-to-left) + chain-agnostic `auto_decode` fallback |
| [`fetch.py`](../solvers/day31_script/fetch.py), [`extract.py`](../solvers/day31_script/extract.py) | start/retry/practice + artifact download with backoff; unpack the AES ZIP(s) |
| [`qdiff.py`](../solvers/day31_script/qdiff.py), [`wdiff.py`](../solvers/day31_script/wdiff.py), [`wdiff2.py`](../solvers/day31_script/wdiff2.py) | Contract diffs: by ID (single), by normalized wording shape (timed), and real-change-only |
| [`contract.py`](../solvers/day31_script/contract.py), [`sufmap.py`](../solvers/day31_script/sufmap.py), [`missing.py`](../solvers/day31_script/missing.py) | Suffix inventory and "what does the old solver not answer" |
| [`timed.py`](../solvers/day31_script/timed.py), [`run_m.sh`](../solvers/day31_script/run_m.sh) | One-process timed runner; gated mastery driver |
| [`batshapes.py`](../solvers/day31_script/batshapes.py), [`adiff.py`](../solvers/day31_script/adiff.py), [`confirm.py`](../solvers/day31_script/confirm.py) | Batch reconstruction dump; answer diff across days; verdict read-back via `op=status` |

Days 1–4 have their own solvers ([`solve_powerplay.py`](../solvers/solve_powerplay.py),
[`solve_hostmost.py`](../solvers/solve_hostmost.py), [`codex_day3/`](../solvers/codex_day3/solve_expansion.py),
[`codex_day4/`](../solvers/codex_day4/dim_solve.py)). The Day 5–8 solvers lived on the Homebase VM and were
not preserved; their logic was folded into `s9.py`/`sdec.py`.

## Label vocabularies the grader accepted

**Roles:** `benign_utility`, `stager`, `dropper`, `downloader`, `uploader`, `launcher`, `impact`,
`staged_chain`, `relay`, `persistence_descriptor`, `advanced_syntax`. `relay-handoff` is `staged_chain` for
JScript/Batch/VBScript but `relay` for Python.

**ATT&CK** (non-polyglot files): benign `none`; stager/downloader `T1105`; dropper `T1140`; uploader `T1041`;
impact `T1486`; persistence `T1053.003`; launcher/chain/relay → the language's execution technique (JScript
and Node `T1059.007`, Batch `T1059.003`, VBScript `T1059.005`, Python `T1059.006`, Bash `T1059.004`).
PowerShell scenarios: resource `T1496`, collection `T1555.003` (`T1005` also accepted), impact `T1486`.
Polyglots and hosts: **whatever the descriptor records** (often the bare `T1059`, sometimes pairs that
contradict the steps).

| Family | Field | Values |
|---|---|---|
| JScript | function / invocation / property style | `declaration`, `named_expression`, `anonymous_expression` / `direct`, `call`, `apply` / `dot`, `bracket_literal`, `mixed` |
| Batch | expansion | `percent`, `delayed`, `call_double`, `for_indirect` (syntax-true from Day 15) |
| Batch | control | `direct`, `goto_dispatch`, `call_subroutine`, `errorlevel_guard`, `if_guard` |
| Batch | graph | from the plan (`linear`, `single`, `same_language`, `fallback_retry`, `cross_language`, …) |
| VBScript | representation | `decimal_pipe`, `decimal_dash`, `decimal_csv`, `reversed_decimal`, `hex_compact`, `hex_colon`, `hex_dash`, `reversed_hex`, `base64_chunks` |
| VBScript | transform | `subtract_modulo_256`, `add_modulo_256`, `single_byte_xor`, `repeating_key_xor`, `rolling_xor`, `reverse_bytes`, `reverse_then_xor`, `identity` |
| VBScript | control | `direct`, `select_case`, `do_once`, `while_once`, `for_once`, `error_guard` |
| Python | syntax / obfuscation / carrier / windows-chain | from the plan (e.g. `closure_factory` / `chr_join` / `hash_based_pyc_current` / `pythonw_hidden_console`) |
| Polyglot | obfuscation | `base64`, `plain_hex`, `hex_base64`, `fragmented_hex`; timed: the `LYR` chain (`b64_rev_hex`, …) |
| Polyglot | stage profile | `single_descriptor`, `two_stage_download_execute`, `three_stage_decode_write_launch`, `cross_language_handoff` (timed variants invent names such as `cobalt_braid`) |
| Host | host profile | `perl_cgi`, `ruby_rack`, `google_docs_sidebar`, `aspx_inline_csharp`, `jenkins_pipeline`, `classic_asp`, `jsp_webshell`, `elixir_phoenix`, `jsp_beanshell`, … (`standalone` for plain polyglots) |

**Advanced-syntax Bash fixtures** (role `advanced_syntax`, `T1059.004`, steps `recognize_syntax>reconstruct_intent`):

| Day | Fixtures → feature / primitive |
|---|---|
| 7 | indirect-expansion → `indirect_expansion`/`parameter_indirection`; token-fragmentation → `token_fragmentation`/`array_token_construction` |
| 8 | associative-arrays → `associative_arrays`/`declare_associative`; array-slicing → `array_slicing`/`indexed_array_slice` |
| 9 | recursive-walk → `recursive_walk`/`bounded_recursive_function`; trap-handler → `trap_handler`/`function_local_trap` |
| 10 | heredoc-reconstruction → `heredoc_reconstruction`/`quoted_heredoc`; here-string → `here_string`/`here_string_read` |
| 11 | nameref-dispatch → `nameref_dispatch`/`declare_nameref`; dynamic-file-descriptor → `dynamic_file_descriptor`/`allocated_file_descriptor` |
| 13 | subshell-pipeline → `subshell_pipeline`/`command_substitution_pipeline`; process-substitution → `process_substitution`/`process_substitution_reader` |
| 14 | getopts-state → `getopts_state`/`option_parser_state`; brace-expansion → `brace_expansion`/`cartesian_brace_expansion` |
| 16 | ansi-c-quoting → `ansi_c_quoting`/`ansi_c_escape_string`; regex-conditional → `regex_conditional`/`bash_regex_match` |
| 20 | coprocess-block → `coprocess_block`/`coproc_declaration`; mapfile-process → `mapfile_process`/`mapfile_process_substitution` |

## Reusable techniques
- **Partial-feedback banking.** A subset submit of all-correct answers returns `accepted` + `remaining` and
  banks them; one wrong answer banks nothing. Use it to learn mappings on untimed attempts, to bisect a failed
  group down to one field, and in timed modes to brute-force a small enum (submit each candidate; the right
  one banks).
- **Submit by file group.** A wrong group points at one specimen, and bisection inside it finds the field.
  Bank the day's new files first.
- **Diff contracts before coding.** `qdiff` on IDs, `wdiff` on normalized wordings for hash-named timed
  contracts, `wdiff2` to ignore cosmetic format hints. `op=status` before `start` already lists the questions.
- **Static brute-force decoding.** Generate every plausible byte array from a material (all representations,
  both orders) × every inverse transform with keys taken from the source, and accept the first output that
  parses as a plan. It absorbed most new codecs without code changes.
- **Use recorded values.** When a specimen records its own role/attack/profile, the grader wants exactly that,
  even when the steps suggest otherwise.
- **One process for timed modes.** start → fetch → compute → submit with backoff on `rate_limited`, exception-safe
  retries (a `ConnectionResetError` once killed a submit loop), answers as strings, and verdicts confirmed
  with `op=status`.

## Hardest moments
- **Day 3, `if_guard`.** 157/159 banked, then about 145 rejected tokens for two Batch control fields. A
  second model's guess broke it. The lesson became the team's playbook for blocked classification tokens:
  they are compositional `<construct>_<qualifier>` snake_case, so enumerate the cross-product rather than
  synonyms.
- **Day 4, VBScript `*_once`.** The same wall for the loop-wrap control labels, solved the same way.
- **Day 5–6 timers.** Hundreds of answers in about 7 seconds with no banking across attempts. Solved with
  parallel chunked submits plus parallel enum candidates, then tuned down when concurrency caused rate-limit
  cascades.
- **Day 9 rebuild.** The earlier solvers were not available locally, so the lane was rebuilt as a static
  decoder in one session, learning a handful of new material representations on the way (`\x`/`%XX` escapes,
  literal concatenation, split quoted chunks, reversed Base64, …).
- **Day 15 grader shift.** The Batch expansion convention used since Day 4 was suddenly rejected on Time
  Trial in favor of syntax-true labels. Untimed regular attempts (new that day) allowed fixing and rebanking on
  the same attempt.
- **Day 23 contract split.** The old solver answered 325 of 1,495 timed questions. Composite labels and
  scenario-dependent PowerShell key layouts were found by by-file banking.
- **Day 21 and Day 30 bookkeeping.** An interrupted morning run left Day 21's timed-mode details
  unrecorded, and a broken pipe hid Day 30's Single Solve verdict. Both led to logging submits to files and
  confirming verdicts with `op=status`.
