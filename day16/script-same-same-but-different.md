# 📜 Same Same, But Different

| | |
|---|---|
| **Day** | 16 |
| **Lane** | 📜 Script Analysis |
| **Challenge ID** | `script-analysis-day-16-obfuscation-equivalence` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day16_script/s9.py`](../solvers/day16_script/s9.py) + [`sdec.py`](../solvers/day16_script/sdec.py) (unchanged copies of Day 15) · [`timed.py`](../solvers/day16_script/timed.py) |

## Prompt
> Several obfuscation families have scrambled the same logic independently, or so they claim. Strip each version down to its semantics, prove which ones are truly equivalent, and expose the variant that quietly changed the plot.

## TL;DR
**1,095 questions** = the Day-15 contract (1,026, unchanged) + 69 new: four **Ruby** polyglots, a Ruby/Rack
host fixture and two advanced Bash fixtures. No equivalence question existed. The Day-15 solver computed
1,095/1,095 unchanged, and all three modes passed in about 2 minutes of solving.

## Artifact
WinZip-AES ZIP (`infected`). New files:

| File | Questions | Notes |
|---|---|---|
| `polyglot-ruby-{benign-utility,downloader,launcher,staged-chain}.rb` | 4 × 11 | `# HUNTRESS_ANALYSIS_V1:<ENC>-…` + `DESCRIPTOR_<HEX> = "…".freeze` + `build_plan_<hex>` |
| `host-ruby-rack-ruby.rb` | 11 | `host_profile=ruby_rack`, role `staged_chain`, attack `T1059`; decorative `INERT_RACK_… = ->(_env) { [200, …] }` lambda |
| `ansi-c-quoting.sh` | 7 | feature `ansi_c_quoting`, primitive `ansi_c_escape_string`, codec `hex_compact\|` |
| `regex-conditional.sh` | 7 | feature `regex_conditional`, primitive `bash_regex_match`, codec `xor_hex\|ec` |

Header encodings seen on the Ruby files: `HEX`, `B64`, `HB64`, `FRAG`. Campaign IDs look like `RUBY-<8hex>`.

## Solution
1. `fetch.py` → `qdiff.py <day15> <day16>` → 0 gone, 0 changed, 69 new.
2. `s9.py <ch> --dir <dir> --show "ruby|ansi-c|regex-cond"` → 1,095/1,095 computed, none unanswered.
   - Ruby polyglots and host: standard header decode ([Day 8](../day08/script-lost-in-translation.md)),
     answered from the recorded fields (benign → `none`, downloader → `T1105`, launcher/staged-chain → `T1059`).
   - Bash fixtures: the Material/Codec brute-forcer ([Day 9](../day09/script-all-the-world-s-a-stager.md))
     handled both the hex material and the single-byte XOR (`xor_hex|ec` = hex material XOR `0xec`).
     Answers: `advanced_syntax`, `T1059.004`, stage count 1, steps `recognize_syntax>reconstruct_intent`,
     campaign `BASHX-<8HEX>`.
3. Single Solve: new files banked first (5 × 11 + 2 × 7 `accepted`), then 10-file batches, the last one CORRECT.

The syntax-true Batch `expansion` rule from [Day 15](../day15/script-crumb-trail.md) was accepted in all
three modes, and no legacy fallback was needed.

## Time Trial & Mastery
- Both came up untimed (`deadline: None`).
- Time Trial: 1,095 answers, one full submit in 4.1 s → CORRECT.
- Mastery: 5,475 answers (5 sets, all in the default artifact), one full submit in 8.0 s → CORRECT.
- No rate limiting.

## Lessons / gotchas
- Eight days running (Day 9 → 16), one new polyglot language per day: MOF → TypeScript → AutoIt →
  AppleScript → MSBuild XML → Perl → Ruby. A host fixture for the new language is now common.
- Codec parameters such as `xor_hex|ec` are hex keys. The brute-forcer seeds its key list from the codec
  string, so new transform names rarely need code.
- Previous: [Day 15](../day15/script-crumb-trail.md) · Next: [Day 17](../day17/script-fetch-quest.md).
