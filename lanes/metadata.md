# 🔎 Metadata Forensics — lane overview

Each metadata challenge hands out a ZIP of evidence files and asks for exact, byte-derived facts about them. The facts
cover file identity (name, size, MD5 / SHA-1 / SHA-256), the first N bytes, BOMs, and one header or structure field per
file format. Every prompt tells a forensic story ("find the impostor", "rebuild deployment groups", "expose the
fabricated cluster"). With two exceptions (Days 30 and 31), the grader asked for one precise field of one new file
type, and the story stayed decoration. Labels are untrustworthy by design: extensions lie, panel numbers are
cosmetic, a "copy" carries another file's name. Every answer has to come from the decompressed bytes.

All 31 challenges were solved in all three modes (93/93 challenge-modes).

## Day by day

| Day | Challenge | What it added |
|---|---|---|
| 01 | [You Must Be This Hash to Ride](../day01/metadata-you-must-be-this-hash-to-ride.md) | Identity inventory: filename, size, MD5 / SHA-1 / SHA-256. Mastery = outer ZIP of per-set ZIPs |
| 02 | [Looks Can Be Deceiving](../day02/metadata-looks-can-be-deceiving.md) | `magic-prefix-hex-16` (first N bytes, N from the id suffix). A PDF disguised as `.bin`. Short-timer desync |
| 03 | [BOM Voyage](../day03/metadata-bom-voyage.md) | `text.utf8_bom_present` (`EF BB BF`). The `Determine <field> for <file>` wording. Consistency gate |
| 04 | [Picture This](../day04/metadata-picture-this.md) | `jpeg.sof_dimensions_pixels` → `WxH` from the SOF marker (stored H then W) |
| 05 | [Chunk Norris](../day05/metadata-chunk-norris.md) | `png.ihdr_dimensions_pixels` (IHDR bytes 16–24). Map sets by nested ZIP, not by label |
| 06 | [Portable Deception](../day06/metadata-portable-deception.md) | `pdf.header_version` (`%PDF-X.Y` in the first 1 KiB, else `none`) |
| 07 | [Seven-Zip, No Relation](../day07/metadata-seven-zip-no-relation.md) | `zip.eocd_total_entries`. Double-nested ZIPs. Found **`op=practice`** and **string-only answers** |
| 08 | [What’s in the Box?](../day08/metadata-whats-in-the-box.md) | `zip.central_directory_member_names`. **First compounding contract** (12 q, 5 mastery sets) |
| 09 | [Built Different](../day09/metadata-built-different.md) | `pe.coff_machine_u16_hex` (`0x014c`). `m9.py`, the field-dispatch solver every later day extends |
| 10 | [Where Do We Begin?](../day10/metadata-where-do-we-begin.md) | `pe.address_of_entry_point_rva_hex`. **`0x%08x` padding required** (unpadded rejected) |
| 11 | [What’s My Name Again?](../day11/metadata-whats-my-name-again.md) | `pe.version_original_filename` from VS_VERSIONINFO (`pefile`) |
| 12 | [Managed Expectations](../day12/metadata-managed-expectations.md) | `dotnet.mvid_guid`: Module MVID from the `#GUID` heap, `bytes_le`, lowercase |
| 13 | [Product Placement](../day13/metadata-product-placement.md) | `msi.product_code_guid`. Pure-Python MSI reader on `olefile`. `{UPPER}` verbatim |
| 14 | [The Shortcut Home](../day14/metadata-the-shortcut-home.md) | `lnk.target_path_windows`. Pure-Python MS-SHLLINK parser |
| 15 | [A Word to the Wise](../day15/metadata-a-word-to-the-wise.md) | `ooxml.external_relationship_targets` (**sorted**). Compounding returns for good (20 q) + SHA-256 **synthesis** question |
| 16 | [Return to Sender](../day16/metadata-return-to-sender.md) | `email.message_id`, angle brackets kept. Timed modes untimed by default |
| 17 | [Hear Me Out](../day17/metadata-hear-me-out.md) | `media.primary_audio_codec_name` → ffprobe name `pcm_s16le`. Pure-Python audio probe |
| 18 | [Frame of Reference](../day18/metadata-frame-of-reference.md) | `media.primary_video_dimensions` → `320x180` after H.264 SPS cropping |
| 19 | [Little Endian on the Prairie](../day19/metadata-little-endian-on-the-prairie.md) | `elf.e_machine_u16_hex` (`0x003e`) using `EI_DATA` byte order |
| 20 | [Universal Appeal](../day20/metadata-universal-appeal.md) | `macho.cpu_type_set` → `["0x0100000c"]` (names rejected). Thin / fat / ar parser |
| 21 | [Package Deal](../day21/metadata-package-deal.md) | `apk.package_name` from binary AXML. v1 / v2 signer extraction |
| 22 | [Main Character Energy](../day22/metadata-main-character-energy.md) | `jar.main_class` from `MANIFEST.MF` (continuation lines). Mastery 6 sets |
| 23 | [Page Me Maybe](../day23/metadata-page-me-maybe.md) | `sqlite.page_size_bytes` (1 → 65536). **Two latent bugs**: suffix collision, sorted CD-names / cputypes |
| 24 | [Event Horizon](../day24/metadata-event-horizon.md) | `evtx.record_count` by walking chunks and records. Filename-question resolution hardened |
| 25 | [Hive Mind](../day25/metadata-hive-mind.md) | `registry.hive_root_name` (root `nk` cell, not the header's embedded file name) |
| 26 | [Before You Go](../day26/metadata-before-you-go.md) | `prefetch.executable_name`. Pure-Python LZXPRESS-Huffman (`MAM\x04`) decompressor |
| 27 | [Packet Loss Prevention](../day27/metadata-packet-loss-prevention.md) | `pcap.packet_count` (classic + pcapng parser with strict validation) |
| 28 | [Where It All Began](../day28/metadata-where-it-all-began.md) | `disk.partition_start_lba_sequence` from GPT (`[34]`) |
| 29 | [Trust Issues](../day29/metadata-trust-issues.md) | `x509.sha256_fingerprint` = SHA-256 of the DER, not of the PEM file |
| 30 | [Seeing Double](../day30/metadata-seeing-double.md) | `relation.identical_sha256_groups`: id groups, sorted, ≥ 2. Near-duplicates and a CRC-broken nested ZIP |
| 31 | [No Artifact Left Behind](../day31/metadata-no-artifact-left-behind.md) | `graph.execution_chain_artifact_ids`: per-format edges, root → terminal, decoy cycle. 540-q mastery |

## How the lane evolved

**Days 1–7: one field, one file.** Each day asked a handful of questions about a single target, and the
difficulty was operational, not forensic:

- **Packaging.** Mastery sets arrive as an outer ZIP of per-set ZIPs (`metadata-day-NN-evidence-0K.zip`), as separate
  0-based deliveries, or double-nested (Day 7).
- **Labels.** Question labels named files that were renamed or cosmetic (Day 5's `panel-003` was really `panel-006`).
- **Timers.** Timed attempts were short (a few seconds). Too many requests, or an attempt expiring between `start` and
  `artifact`, left the solver holding one attempt's questions and another attempt's files (Days 2, 3, 5).

The lasting fixes were: gather everything in one request when possible, keep the full nested path of every member,
resolve by the container named left of `->`, and gate submits on consistency.

**Days 8–9: the first compounding contract.** Day 8 asked every earlier family at once: the evidence-note
identity block plus one question per Day 4–7 file type, plus the new field. That made 12 questions per set, and Day 9
had 13. Answer ids encode the day that introduced the artifact (`d04-jpeg-001-…`, `d07-zip-001-…`). `m9.py`
introduced the pattern every later solver follows: classify the question by `Determine <family.field> for <file>.`
and dispatch through a table of extractors.

**Days 10–14: single-field days again.** Every mode asked only the new field: PE entry point, PE version resource,
.NET MVID, MSI ProductCode, LNK target. Mastery had 2 sets. By then the lane was solved without supervision. Day 9 was
the first day the scheduled 09:00 ET headless agent solved on its own from WSL. From Day 10 three lane agents ran in
parallel on one GM token, and that sharing is why rate-limit backoff (`gmx.GMX`) was added on Day 11.

**Days 15–31: compounding for good.** The timed modes became one long contract that grew by one question a day,
from 20 on Day 15 to 36 on Day 31:

- a sampled identity block (`roster` / `evidence-note` / `evidence-note-copy` filename, size and digests);
- prefix hex and BOM;
- one question per family since Day 4;
- a **synthesis** question: "compact JSON array of the named files in ascending SHA-256 order".

Mastery sets grew from 5 to 15 (6 on Day 22, then +1 per day), so Day 31 mastery was 15 × 36 = **540 answers** in
one submit. Single Solve asked only the new field, which made it the place to probe a new field's format. From
Day 15 on, the timed metadata modes came up as regular untimed attempts (`deadline: None`; a Hall of Fame run needs
`run_for_time:true`), so correctness mattered and speed did not.

**The solver chain.** `m15.py` re-merged every extractor after the Days 10–14 detour had dropped the Day 4–7 ones. Each
later day added one module (`media.py`, `video.py`, `macho.py`, `apk.py`, `jar.py`, `sqlite.py`, `evtx.py`,
`reghive.py`, `prefetch.py`, `pcap.py`, `disk.py`, `x509.py`, `rel30.py`, `graph31.py`) and an `mNN.py` that wraps the
previous one by monkey-patching `m15.field_value` / `solve`. All parsers are pure Python (stdlib plus `pyzipper`,
`pefile`, `dnfile`, `olefile`, `cryptography`), so no external tool sits in the solve path. WSL had no MSI tooling at
all. `aapt` / apktool and `openssl` were used only to cross-check the APK and certificate parsers. From `m10.py` on,
every solver has `start --save <dir>` to compute and store an attempt, and `none --dir <dir> [--submit]` to
recompute or submit it offline. That loop caught the Day 24 filename bug before it cost a submit, and on Day 30 it
cross-checked all 14 mastery sets.

### Answer conventions the grader enforced

| Kind | Convention (as accepted) |
|---|---|
| Every answer | a JSON **string**, even integers (`"2"`); raw numbers → `invalid_answers` |
| Digests | lowercase hex accepted (`case_insensitive`); no prefix |
| First N bytes | `data[:N].hex()`, N from the `-hex-<N>` suffix of the id |
| Dimensions | `<width>x<height>` (JPEG SOF, PNG IHDR, cropped H.264 SPS) |
| Fixed-width integers | `0x` + zero-padded to the field width: `0x%04x` (u16 machine fields), `0x%08x` (RVA, Mach-O cputype) |
| GUIDs | in their native form: MVID lowercase 8-4-4-4-12; MSI ProductCode `{UPPERCASE}` with braces |
| Headers / strings | verbatim (`Message-ID` with `<…>`, `OriginalFilename`, root key name, executable name) |
| Codec names | ffprobe vocabulary (`pcm_s16le`) |
| JSON arrays | compact (`separators=(",", ":")`). Order-free sets are compared **sorted** (OOXML targets, CD member names, Mach-O cputypes, relation groups) |
| Missing field | the literal `none` |

## Reusable techniques
- **Gather, then map structurally.** Recursively unzip (AES `infected` levels included) into a list of
  `(nested/path, bytes)`, and map each question to a member by its own `-> member` hint, disambiguated by the
  container on the left. Use the set index or the content signature only as fallbacks.
- **Filename questions.** The member of the set's container whose name, minus extension and an optional 6-hex tag,
  equals the id stem: `^<stem>(-[0-9a-f]{6})?\.\w+$` (Day 24).
- **Dispatch on question text, not id suffix.** `-size-bytes` meant "file size" until Day 23 introduced
  `sqlite-page-size-bytes`.
- **Probe formats on the untimed single** with one-answer submits. A wrong candidate banks nothing and costs nothing,
  and a right one banks. On compounding timed attempts, a one-answer subset submit (`accepted`, `remaining: N`)
  confirms a new convention before the big submit (Days 30, 31).
- **Bisect a failed full submit** with one-answer partial submits (Day 23).
- **Build the parser for the story, answer the field.** Every day's module parsed far more than the asked field (EVTX
  claimed vs. walked counts, hive checksums, APK signers, JAR launchers, pcap validity, GPT backup headers) and printed
  a diagnostic line per file. No twist came, but a malformed variant would have been visible before the submit.
- **Refuse unknown shapes.** `graph31.py` raises unless the case graph is exactly "one chain plus cycles", and
  `m21.py --partial` refuses incomplete answer sets. A refusal costs minutes, while a guess fails a 540-answer submit.

## Hardest moments
- **Day 2: the regenerating attempt.** Eleven artifact requests crossed a seconds-long mastery deadline. The attempt
  regenerated mid-gather, and decoy files (`mutation-baseline.dat`, `one-byte-off.dat`) seemed to answer the old
  questions. The fix was one request per attempt.
- **Day 3: inconsistent timed attempts.** `start` and `retry` resumed an attempt whose delivery did not contain the
  asked file. It had to expire before a fresh one could start, which led to the consistency gate.
- **Day 7: "rotation exhausted".** The mastery's ranked attempts were used up (`uar` 0, `retry` →
  `rotation_exhausted`). Reading `op=openapi` turned up `op=practice` ("continue unranked after exhaustion"), an untimed
  unlimited attempt, and showed that answers must be strings. Together they made every mode of every lane solvable for
  the rest of the event.
- **Day 10: padding.** `0x65bd0` was graded `incorrect` and `0x00065bd0` CORRECT. From then on, "pad to the field
  width" applied to every hex field.
- **Day 15: "exact order" that meant sorted.** OOXML external targets in document order were rejected.
- **Day 23: two silent bugs at once.** A suffix collision answered a page size with a file size. The grader also turned
  out to sort central-directory names and Mach-O cputypes, which Days 8–22 had never revealed because those inputs
  were already sorted. Both were found by bisecting with one-answer partial submits.
- **Day 24: the filename questions.** Inferring "the roster" from neighbouring questions failed on 2 of 232 mastery
  answers (no roster sibling in one set, a `-copy` sibling picked in another). It was caught offline before the submit.
- **Day 26: compression only on the single.** The Single Solve prefetch file was `MAM`-compressed, which required a
  from-scratch LZXPRESS-Huffman decoder. Every timed variant was uncompressed.
- **Day 30: shape change between modes.** The single had a truthful manifest and named files. The timed clusters had
  neither, and added one-byte near-duplicates plus a nested ZIP with a broken CRC that crashed the shared unzip helper.
- **Day 31: the decoy cycle.** The first version of `graph31.py` refused 8 of 15 mastery sets because of four unseen
  terminal forms, and edges with broken PowerShell quoting raised the question of whether they count. A one-answer probe
  on set 8 settled it (`accepted`, `remaining: 539`) before the 540-answer submit.
