# ⚙️ Binary Reverse Engineering — lane overview

The binary lane is static reverse engineering at scale. Each challenge ships an evidence ZIP (WinZip-AES,
password `infected`) full of small, inert binaries built by the organizers' generator, and asks for exact
analysis facts: header fields, section and symbol lists, a disassembly, and above all the **embedded
configuration** that every unit hides somewhere. The lane is **compounding**: each day adds one new
language or container as unit `dNN`, and every earlier unit stays in the bundle with the same (and
sometimes extended) questions. Day 1 asked 9 questions per binary; Day 31 asked 434 per attempt and 6,510 in
mastery, covering 31 units from C to Neko bytecode.

All 31 lane challenges were solved in all three modes (93/93), plus the day-30 5-point standard challenge
⚙️ SHA1-Hulud (single mode only).

## Challenges

| Day | Challenge | What it added |
|---|---|---|
| 01 | [ELF Aware](../day01/binary-elf-aware.md) | C ELF basics (class, machine, type, entry, `.huntress` marker, `recover_code` immediate in decimal); per-slot answer ids and decoy slots |
| 02 | [Mangled](../day02/binary-mangled.md) | C++ that is ELF **or** PE per attempt; vtable/typeinfo symbols (COMDAT `.text$` / `.rdata$` names on PE); first XOR'd `HCFG` config |
| 03 | [Table Manners](../day03/binary-table-manners.md) | .NET 8 DLL (`pe_cli`, `i386`, `v4.0.30319`); HCFG header parsed; section/symbol lists; the `pe_cli` block |
| 04 | [Go Fish](../day04/binary-go-fish.md) | Go ELF (`x86-64`, not `amd64`); compounding starts (`d01`–`d04`) |
| 05 | [Rust Belt](../day05/binary-rust-belt.md) | Rust ELF with decoy HCFG blocks; `raw_decode` + "most complete config" selection; parallel timed submits |
| 06 | [Pool Party](../day06/binary-pool-party.md) | Java jar: HCFG as a Base64 constant-pool string (`SENG…`); `hcfg_version` |
| 07 | [Routine Check](../day07/binary-routine-check.md) | 5 MB Kotlin jar; scan top-level classes first; submit-job count as the real time limit |
| 08 | [Swift Justice](../day08/binary-swift-justice.md) | 67 MB Swift ELF (Base64 config, raw decoy); integer `machine`/`elf_class`; +2 fields on old units; practice-mode grind |
| 09 | [Nimble](../day09/binary-nimble.md) | Nim ELF; `hcfg_offset` (offset of the Base64 text); consolidated `b9.py` |
| 10 | [Zig Zag](../day10/binary-zig-zag.md) | Zig ELF-or-PE; dedicated `.hcfg` section; `has_hcfg_section`; first scheduled headless run |
| 11 | [D-Day](../day11/binary-d-day.md) | D (ldc/gdc) ELF, Base64 literal; backoff for agents sharing one token |
| 12 | [Pascal's Wager](../day12/binary-pascal-s-wager.md) | Free Pascal ELF, raw record in `.data`; offset of the raw magic |
| 13 | [Crystal Clear](../day13/binary-crystal-clear.md) | Crystal ELF, Base64 text inside a Crystal `String` object |
| 14 | [Selective Memory](../day14/binary-selective-memory.md) | GNUstep Objective-C ELF with a `.hcfg` section |
| 15 | [Stripped](../day15/binary-stripped.md) | Symbolized + stripped ELF pair; per-role fields; sha order = ZIP order; mastery 5 sets |
| 16 | [Wasm Up](../day16/binary-wasm-up.md) | WebAssembly pair; `wasm` / `wasm32`; record in the data section |
| 17 | [Decoder Ring](../day17/binary-decoder-ring.md) | Ada (GNAT) ELF; 32 "deep" fields on old units; the `hcfg_storage` block and the official enum fix |
| 18 | [Flow State](../day18/binary-flow-state.md) | gfortran ELF (jump-table dispatch, not graded); one-line solver change |
| 19 | [Jack in the Box](../day19/binary-jack-in-the-box.md) | GnuCOBOL ELF with a packed `PK19` overlay (`ror8(b ^ k2, 3) ^ k1`); questions now spell out layouts |
| 20 | [Resourceful](../day20/binary-resourceful.md) | GHC Haskell ELF with an `RS20` resource overlay + hashed scratch trailer; format enum incl. `neko_bytecode` |
| 21 | [Shared Custody](../day21/binary-shared-custody.md) | OCaml loader + `.cmxs` plugin; config only in the plugin |
| 22 | [Bridge Troll](../day22/binary-bridge-troll.md) | F# assembly + `FSharp.Core.dll`; picking the primary DLL; duplicate config copies |
| 23 | [Trust Issues](../day23/binary-trust-issues.md) | VB.NET assembly with anti-analysis predicates (not graded); `xor_key_hex`; superset field handler |
| 24 | [Spot the Difference](../day24/binary-spot-the-difference.md) | Scala vulnerable/corrected jar twins; constant-pool walk (Base64 ≥ 80 chars); byte-equal configs |
| 25 | [Out of Bounds](../day25/binary-out-of-bounds.md) | Clojure twins, same shape; `twin_jar_fields()`; contract diff before coding |
| 26 | [Crash Course](../day26/binary-crash-course.md) | Groovy jar with `crash/trace.json`; fault method, frame/method match, method count |
| 27 | [Compiler Says What](../day27/binary-compiler-says-what.md) | GCC vs TCC ELF builds; **backward** raw HCFG scan |
| 28 | [Family Resemblance](../day28/binary-family-resemblance.md) | Family + false-friend ELFs; **54 new fields on old units**; three ambiguities settled by probing |
| 29 | [Fraternal Twins](../day29/binary-fraternal-twins.md) | `-O0` / `-O3` ELF twins |
| 30 | [Campaign Trail](../day30/binary-campaign-trail.md) | Three Neko bytecode modules; `HGRF` record; `graph.config.x` names the object, not a key |
| 30 | [SHA1-Hulud](../day30/binary-sha1-hulud.md) | 5-point standard crackme: Rust PE, self-decrypting SHA-1 variants, VEH, environmental keying; solved by Unicorn emulation |
| 31 | [Final Boss](../day31/binary-final-boss.md) | Gauntlet ELF with an `HGAU` overlay record; `gauntlet.trace_branch` → `trace.branch` |

## How the lane evolved

**Orientation (Days 1–3).** Day 1 taught the answer conventions (exact labels like `ELF64` / `x86-64` /
`ET_EXEC`, `none` for absent fields, decimal immediates) and the answer-id structure (per-slot, per-set). Day 2
introduced the two ideas that run through the whole event: a unit's container can change between attempts
(ELF or PE), and the configuration lives in an **HCFG record**:

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `HCFG` (later also `HGRF`, `HGAU`) |
| 4 | 1 | version |
| 5 | 1 | one-byte XOR key |
| 6 | 2 | payload length, little-endian |
| 8 | 4 | CRC32 of the decoded payload, little-endian |
| 12 | n | JSON payload XOR'd with the key (`campaign`, `domain`, `url`, `mutex`, later `ipv4`, paths, `service`, `host_model`) |

Day 3 added a .NET unit and produced the lane's first hard block: the generator label `pe_cli`.

**Compounding by hand (Days 4–9).** Each day kept the previous bundle and added a language (Go, Rust, Java,
Kotlin, Swift, Nim). The work shifted from analysis to answer formats and speed. Questions were still a
generic template ("What is the exact analysis X value…"), so new formats were learned by banking candidates
in the untimed single solve. Timed windows were short (about 6–7 s on Days 3–6, ~13 s on Day 7, ~26 s for
Day-8 mastery), and the playbook became: one process, parallel single-answer submits for uncertain fields,
chunked submits for the rest, and a cap on workers to stay under the rate limiter. Day 8 added fields to old
units for the first time and was the only day whose mastery had to be finished through `op=practice`. Day 9
consolidated everything into `b9.py`.

**The 10-field daily unit (Days 10–16).** From Day 10 a scheduled headless agent solved the lane each morning
at 09:00 ET from a WSL toolchain. Each new unit reused one of two shapes: the Base64-literal shape
(`hcfg_offset`) or the `.hcfg`-section shape (`has_hcfg_section`). The procedure: diff the question ids,
extend a handler tuple, bank the new unit first in single solve, then run each timed mode in one process.
Most days took two to five minutes. Mastery grew from 3 to 5 sets. From Day 15 on, the timed starts usually carried no visible deadline
(regular, untimed-scored play; Day 18 was an exception with 80 s / 265 s windows), and the solver finished
well inside any window anyway.

**Deep fields and the grader fix (Day 17).** 44 new questions, 32 of them on old units, and two free-text
`hcfg_storage` labels that no amount of guessing found. An organizer fix converted them into an enum with a
written decision rule. After this, new questions were written as full procedures ("Use the unique d21--
member whose basename ends plugin.cmxs. Read the ELF e_machine field and submit its unsigned base-10 numeric
value…"), and the lane never blocked again.

**Containers and roles (Days 18–31).** New units became 12–14 fields with explicit lookup rules: overlays
after the section headers (`PK19` packed, `RS20` resource, `HGAU`), a plugin, managed assemblies with
dependencies, twin jars that must decode to byte-identical configs, compiler and optimization twins, a
family with a false friend, and Neko bytecode. Prompts promised call graphs, patch diffs, crash triage and
compiler attribution; the questions almost never asked about them, and every writeup notes where a prompt
was flavor. Day 28 was the exception in size, adding two rule-specified fields to every older unit. Mastery
grew by one set a day from Day 22 (6 sets) to Day 31 (15 sets), and downloading the deliveries became the
main cost (about 20–35 s per mastery run).

### Question growth

| Day | 3 | 5 | 6 | 7 | 8 | 9 | 10 | 13 | 16 | 17 | 20 | 24 | 27 | 28 | 29 | 30 | 31 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Single-solve questions | 24 | 40 | 48 | 56 | 80 | 90 | 100 | 130 | 160 | 204 | 240 | 288 | 324 | 392 | 406 | 420 | 434 |
| Mastery sets | 2 | 2 | 2 | 2 | 5 | 5 | 3 | 3 | 5 | 5 | 5 | 8 | 11 | 12 | 13 | 14 | 15 |

### Where the config hides

| Carrier | Units |
|---|---|
| Raw record in a code/data section | `d02`, `d03` (static byte array), `d04`, `d05` (with decoys), `d12` (`.data`), `d17`, `d18` (`.rodata`), `d22`/`d23` (body and file end) |
| Raw record found by **backward** scan | `d27`, `d28`, `d29`; `d30` (`HGRF`), `d31` (`HGAU`) |
| Base64 text starting `SENG` (= Base64 of `HCFG`) | `d06`/`d07`/`d24`/`d25`/`d26` (class-file constants), `d08` Swift, `d09` Nim, `d11` D, `d13` Crystal |
| Dedicated `.hcfg` section | `d10` Zig, `d14` Objective-C, `d15` ELF pair |
| WebAssembly data segment | `d16` |
| Overlay after the section-header table | `d19` (`PK19`, packed), `d20` (`RS20` resource), `d31` (`HGAU`) |
| Second member | `d21` (`.cmxs` plugin; the loader has none) |

### Label vocabulary the grader accepted

| Field | Accepted values |
|---|---|
| `format` | `elf`, `pe`, `pe_cli` (managed .NET PE), `jar`, `wasm`, `neko_bytecode` |
| `architecture` | `x86-64` (also for Go, whose own name is `amd64`); `wasm32` |
| `machine` | labels for `d01`/`d03`-style units (`x86-64`, `i386`); **integers** from `d08` on (`62` ELF, `34404` AMD64 PE) |
| `elf_class` | `ELF64` for `d01`; `64` (bits) for `d08` |
| `hcfg_storage` | `base64`, `raw`, `raw_const_array`, `raw_hcfg_section`, `wasm_data_segment` |
| hex fields | `0x%08x` for CRC32, `0x%02x` for XOR keys, lowercase `0x…` entry points |
| lists | compact JSON (`separators=(",",":")`); `section_names` starts with `""` (section 0) |
| booleans | `true` / `false` |
| trace branch | `success` / `decoy` / `failure` |

## Reusable techniques
- **One growing solver.** `b9.py` → `b10.py` → … → `b31.py` is a single lineage
  ([`solvers/day31_binary/b31.py`](../solvers/day31_binary/b31.py) handles `d01`–`d31` in any mode). Each day
  adds a `dNN_fields()` function and a hook; unit files are matched by their `dNN-` prefix, never by full
  name or position.
- **Contract diff first.** `op=status` works before `start` and returns the full question list. `qdiff.py`
  (ids gone / new / reworded) plus reading the new question texts turns every day into a known delta.
- **Generic HCFG parser.** Find every magic, validate bounds + CRC32 + JSON, and pick by the day's rule
  (first, last, unique, backward, "most complete"). Parse JSON with `raw_decode`. Make the magic a parameter.
- **Container-agnostic facts.** Derive `format` from magic bytes every time; `machine_int()` reads ELF
  `e_machine` or COFF `Machine`; section names come from pyelftools or the PE section table. Old units can
  switch between ELF and PE per delivery (`d02`, `d04`, `d10`).
- **Banking as a probe.** In untimed single solve, correct partial submits return `accepted` + `remaining`
  and are kept, while a batch with any wrong answer banks nothing. Bank confident fields, then try each
  uncertain field (or each reading of an ambiguous rule) alone. `--split-on-fail` re-submits per
  `(set, dNN)` group to isolate a wrong unit.
- **Timed modes in one process.** start → parallel delivery fetch → compute → submit; chunk deterministic
  answers, use parallel singles only for real enums, back off on `rate_limited` and empty responses.
- **Tooling.** Python with `pyzipper` (WinZip-AES), `pyelftools`, `capstone`, `pefile`, `dnfile`; `readelf`,
  `objdump`, `nm`; `ilspycmd` (9.1.0.7988 for net8) and `javap` for reading, never for grading; a
  hand-written LEB128 walker for WebAssembly; a hand-written constant-pool walker for class files; Unicorn
  for SHA1-Hulud.

## Hardest moments
- **Day 3, `pe_cli`.** 23 of 24 fields banked; the .NET format label rejected `pe`, `dotnet`, `msil`,
  `pe32`, `clr` and dozens of compounds. An organizer said it was working as intended. Another model
  (OpenAI Codex) proposed `pe_cli`, which banked. The question was later reworded to describe a
  "container_runtime token".
- **Day 8, Swift mastery.** 400 answers over five ~31 MB deliveries against a ~26 s ranked window from a
  2-core VM. The ranked rotation was drained with `retry`, then the mode was finished untimed with a single
  `op=practice` call and a gentle 5-worker grind. Calling `practice` a second time wipes all banked answers.
- **Day 17, `hcfg_storage`.** Two free-text labels blocked the lane from the 09:00 ET release. 816 tokens
  were rejected, including every piece of the right answers but never the exact joins. At about 12:18 ET an
  organizer announced in the event chat that the questions had objective answers the Game Master did not
  explain, and changed them into an enum with a decision procedure; `raw_const_array` (`d12`, raw record in
  `.data`) and `raw_hcfg_section` (`d14`, record in a `.hcfg` section) then banked and all three modes
  finished within the hour. The lesson kept for later days: labels are compositional
  `<category>_<descriptor>` tokens, so enumerate prefix × artifact-derived descriptor, and re-fetch the live
  question, because organizers fix graders mid-event.
- **Day 28, ambiguous rules.** Three readings had to be probed: UTF-16LE `decoy` at any alignment,
  `SHT_SYMTAB`-only symbol counts, and COFF `NumberOfSections` for a PE answering an "ELF e_shnum" question.
- **Days 30–31, named paths.** `graph.config.campaign` and `gauntlet.trace_branch` named the decoded object,
  not JSON keys. A first draft returned `none` everywhere; printing answers before submitting caught it.
- **SHA1-Hulud.** The only traditional crackme: self-decrypting, exception-driven SHA-1 variants and silent
  environmental keying, where a wrong environment does not crash but decrypts to noise. The TLS callback that
  runs before `main` was the last missing piece. The first agent stopped when a safety classifier halted it;
  the binary agent solved it by emulating the code in Unicorn with stubbed OS calls (never native), and
  flagged that as a judgment call against the "never execute artifacts" rule. Two decoy plaintexts also
  pass the program's own check; the accepted one was the only candidate in the event's flag format.
