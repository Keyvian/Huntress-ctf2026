# 📜 The Butler Did It

| | |
|---|---|
| **Day** | 20 |
| **Lane** | 📜 Script Analysis |
| **Challenge ID** | `script-analysis-day-20-jenkins-pipeline-intrusion` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day20_script/s9.py`](../solvers/day20_script/s9.py) + [`sdec.py`](../solvers/day20_script/sdec.py) (identical copies of Day 19) · [`timed.py`](../solvers/day20_script/timed.py) |

## Prompt
> A Jenkins Pipeline splits its Groovy stages between controller and agent, and not every step runs where it appears to. Recover the pipeline's intent, separate controller semantics from agent semantics, and trace the modeled build into its prior-language stages.

## TL;DR
**1,329 questions** = the Day-19 contract (1,249, unchanged) + 80 new: four **Groovy** polyglots, a Jenkins
Pipeline host, a **classic ASP / VBScript host for an older language**, and two advanced Bash fixtures. No
controller-vs-agent question existed. The Day-19 solver decoded all 80 new questions with **zero code changes**.

## Artifact
WinZip-AES ZIP (`infected`), 140 fixtures. New files:

| File | Questions | Notes |
|---|---|---|
| `polyglot-groovy-{benign-utility,downloader,launcher,staged-chain}.groovy` | 4 × 11 | `final String descriptor_<hex> = "…"`, `def buildPlan_<hex> = { -> [descriptor: …].asImmutable() }`; campaign `GROOVY-<8hex>` |
| `host-jenkins-pipeline-groovy.groovy` | 11 | HB64 header + descriptor + a decorative declarative `pipeline { agent none; stages { stage('Analyze') { steps { echo 'inert-analysis-fixture' } } } }` |
| `host-classic-asp-vbscript.vbs` | 11 | `<%@ Language=VBScript %>` page, `' HUNTRESS_ANALYSIS_V1:B64-…` comment, `Dim descriptor_<hex>` + `Function buildPlan_<hex>()`; campaign `VBSCRIPT-<8hex>` |
| `coprocess-block.sh` | 7 | feature `coprocess_block`, primitive `coproc_declaration`, codec `reversed_base64\|` |
| `mapfile-process.sh` | 7 | feature `mapfile_process`, primitive `mapfile_process_substitution`, codec `base64_literal\|` |

## Solution
1. `fetch.py` + `extract.py` → `qdiff.py <day19> <day20>` → 0 gone, 0 changed, 80 new.
2. `s9.py --show "groovy|jenkins"` → 1,329/1,329 computed statically. The classic-ASP and Bash answers were
   also checked by eye against the raw specimens.
   - Groovy polyglots and both hosts: the `polyglot-`/`host-` id prefixes route every answer to the decoded
     descriptor ([Day 8](../day08/script-lost-in-translation.md)). The Jenkins host decoded to
     `host_profile=jenkins_pipeline`, role `staged_chain`, attack `T1059`, obfuscation `hex_base64`, stage
     profile `three_stage_decode_write_launch`, next language `batch`, steps
     `decode_embedded>write_file>dispatch_process`. The classic-ASP host has `host_profile=classic_asp`, role
     `staged_chain`, attack `T1059`.
   - Bash fixtures: the generic Material/Codec brute-forcer handled both new codecs (string-reversed
     Base64 and plain Base64). Answers: `advanced_syntax`, `T1059.004`, stage count 1, steps
     `recognize_syntax>reconstruct_intent`, campaign `BASHX-<8HEX>`.
3. Single Solve: bank the eight new files first
   (`--only "groovy|jenkins|classic-asp|coprocess|mapfile"`), then the rest in 10-file batches, the last one CORRECT.

## Time Trial & Mastery
- Time Trial: regular attempt (`deadline: None`), one full submit in 3.1 s → CORRECT.
- Mastery: 6,645 answers (5 sets) from a 650 KB default artifact, one full submit in 5.1 s → CORRECT.
- Syntax-true Batch expansion accepted again. No rate limiting.

## Lessons / gotchas
- The lane can **back-fill** host fixtures for earlier languages. `host-classic-asp-vbscript.vbs` was not in
  the Day-19 artifact. Always diff the whole contract rather than grepping for the day's language.
- Mastery stayed at 5 sets (it grew to 6 on [Day 22](../day22/script-next-next-finish.md)).
- Previous: [Day 19](../day19/script-sharp-practice.md) · Next: [Day 21](../day21/script-actions-speak-louder.md).
