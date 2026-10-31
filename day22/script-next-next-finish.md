# 📜 Next, Next, Finish

| | |
|---|---|
| **Day** | 22 |
| **Lane** | 📜 Script Analysis |
| **Challenge ID** | `script-analysis-day-22-installer-script-chain` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day22_script/s9.py`](../solvers/day22_script/s9.py) + [`sdec.py`](../solvers/day22_script/sdec.py) (identical copies of Day 21) · [`timed.py`](../solvers/day22_script/timed.py) |

## Prompt
> An NSIS installer script clicks through its own setup wizard while carrying a little something extra. Separate the real setup actions from the modeled payload behavior, and recover every cross-language handoff from the final bytes. You won't need to press Next once.

## TL;DR
**1,417 questions** = the Day-21 contract (1,373, unchanged) + 44 new: four **NSIS** installer-script
polyglots. Zero solver changes. Mastery grew from 5 to **6 sets** (8,502 answers). This was the last day the
"copy yesterday's solver, bank the new language" routine was enough for every mode. Day 23 rewrote the
timed contract.

## Artifact
WinZip-AES ZIP (`infected`). New: `polyglot-nsis-{benign-utility,downloader,launcher,staged-chain}.nsi`,
11 questions each (role, attack, adapter, campaign, url or file-path, stage-count, steps, host-profile,
obfuscation, stage-profile, next-language).

```nsis
; HUNTRESS_ANALYSIS_V1:<ENC>-<payload>
Unicode True
Name "Huntress Analysis <8hex>"
OutFile "huntress-<8hex>.exe"
Section …
  StrCpy $0 "<same payload>"
SectionEnd
```

One header encoding per file (`HB64`, `FRAG`, `HEX`, `B64`). The installer directives are decorative.

## Solution
1. `fetch.py` + `extract.py` → `qdiff.py <day21> <day22>` → 0 gone, 0 changed, 44 new.
2. `s9.py --show nsis` → 1,417/1,417 computed statically. The decoded payload is the usual
   `v=3|language=nsis|role=…|attack=…|adapter=…|host_profile=standalone|obfuscation_profile=…|stage_profile=…|next_language=…|stage_count=…|steps=a,b,c|campaign_id=NSIS-<8hex>|url=…|file_path=…`
   ([Day 8](../day08/script-lost-in-translation.md)). The `polyglot-` prefix routes
   role/attack/host_profile/obfuscation_profile/stage_profile/next_language/stage_count/steps to the plan,
   and campaign/url/file-path/adapter go through the key map.
3. Values on the Single Solve attempt (campaign IDs elided):

| File | role / attack | adapter | steps | obfuscation | stage profile | next language |
|---|---|---|---|---|---|---|
| benign-utility | `benign_utility` / `none` | `local_parser` | `decode_embedded>write_file>dispatch_process` (3) | `hex_base64` | `three_stage_decode_write_launch` | `powershell` |
| downloader | `downloader` / `T1105` | `http_client` | `profile_host>decode_configuration>dispatch_language` (3) | `fragmented_hex` | `cross_language_handoff` | `jscript` |
| launcher | `launcher` / `T1059` | `process_builder` | `decode_configuration>return_configuration` (2) | `plain_hex` | `single_descriptor` | `batch` |
| staged-chain | `staged_chain` / `T1059` | `operation_graph` | `acquire_remote>dispatch_process` (2) | `base64` | `two_stage_download_execute` | `vbscript` |

   The steps never "explain" the recorded role (a benign file with dropper steps, a launcher with
   benign-looking steps). Read each field as recorded.
4. Single Solve: NSIS groups banked first (`--only nsis`), then the rest in 10-file batches, the last one CORRECT.

## Time Trial & Mastery
- Time Trial: regular untimed attempt (`deadline: None`), 1,417 answers, one full submit in 2.8 s → CORRECT.
- Mastery: **6 sets**, 8,502 answers, all in the 818 KB default artifact. One full submit in 6.4 s → CORRECT.
  `timed.py` handles any set count via the default artifact plus delivery probing.
- The morning automation missed its 09:00 ET slot this day, so the lane ran in a manual relaunch in the
  afternoon (about 19:45 UTC). That had no effect on the solve itself.

## Lessons / gotchas
- Fourteen days running (Day 9 → 22), the same reuse loop worked: diff the whole contract, reuse the solver,
  bank the new files first, then one-shot the timed modes.
- Previous: [Day 21](../day21/script-actions-speak-louder.md) · Next: [Day 23](../day23/script-press-start-to-decode.md).
