# ⚙️ Family Resemblance

| | |
|---|---|
| **Day** | 28 |
| **Lane** | ⚙️ Binary Reverse Engineering |
| **Challenge ID** | `binary-reverse-engineering-day-28-family-clustering` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day28_binary/b28.py`](../solvers/day28_binary/b28.py) (`d28_fields()`, `d28_new_fields()`) · [`qdiff.py`](../solvers/day28_binary/qdiff.py) |

## Prompt
> These binaries might be related — or they might just look alike. Cluster them by behavior, watch out for false friends, and sort the family from the strangers.

## TL;DR
The largest delta since Day 17: **68 new questions**. Fourteen are for the new `d28` unit (three ELFs: two
family members and a "false friend" with a different config); the other **54 add two fields to each older
unit** `d01`–`d27`, each with its exact lookup rule written in the question. Three answers needed a choice
between two readings of the rule; each was probed with its own untimed single-solve submit. Single solve
and time trial each needed one such fix; mastery passed on the first submit.

## Artifact
WinZip-AES ZIP (password `infected`). New members in ZIP order: `d28--…-family-a.elf`, `…-family-b.elf`
and `…-false-friend.elf` (about 22.9 KB each, x86-64).

`d28` fields: SHA-256 × 3, per-role `format` (`elf`) and `machine` (`62`), the common family
`config_{campaign,domain,mutex,url}` (family-a and family-b payloads must be byte-for-byte equal; the false
friend is excluded) and `false_friend_config_campaign` (an `FF28-…` campaign with a decoy domain). Each
member has one HCFG record at offset 22536, found with the [Day-27](../day27/binary-compiler-says-what.md)
backward scan.

## Solution

### The d28 unit
Roles come from the file-name suffixes, so "clustering by behavior" reduces to: decode the backward-scanned
HCFG of each member, confirm family-a == family-b, answer the family config from them and the false-friend
campaign from the third file.

### 54 fields on old units
A sample of what was added (all rules were spelled out in the question text):

| Unit(s) | New field(s) |
|---|---|
| `d01` | `structural_artifact_count`, `structural_ordered_set_sha256` (SHA-256 of the `:`-joined member hashes) |
| `d02` | `vtable_symbol` via an explicit symbol-table traversal (COFF symbol table when `d02` is PE), `config_host_model` |
| `d03`, `d22`, `d23` | `cli_runtime` (COR20 header `MajorRuntimeVersion.MinorRuntimeVersion` = `2.5`), `has_decoy_branch` |
| `d05` | `symbol_count` |
| `d06`, `d07`, `d26` | `class_count`, `class_name`, `method_names_sha256` (sorted names, newline-joined) |
| `d08`–`d14` | missing `hcfg_version` / `xor_key_hex` values: first CRC-valid record in a Base64 run (`[A-Za-z0-9+/]{100,}={0,2}`) for the Base64 carriers, first literal record for `d10`/`d12`/`d14` |
| `d09`, `d12`, `d17` | runtime predicates `has_nim_runtime`, `has_fpc_runtime`, `has_gnat_runtime` |
| `d10` | `section_count` |
| `d11`, `d13`, `d18` | symbol counts by regex (`d_symbol_count`, `crystal_symbol_count`, `handler_symbol_count`), `handler_symbols_sha256` |
| `d15`, `d16` | config of the other twin (`symbolized_config_*`, `direct_config_*`) |
| `d17` | `conditional_branch_opcode_count` in `.text` (bytes `0x70`–`0x7f` plus `0x0f 0x80`–`0x8f`) |
| `d19` | `packing_key_1_hex`, `packing_key_2_hex` (the `k1`/`k2` bytes of the `PK19` header) |
| `d20` | `overlay_size` |
| `d21` | `plugin_config_crc32_hex`, `plugin_hcfg_offset` |
| `d24`, `d25` | `vulnerable_config_*` |

### Three ambiguous readings, settled by probing
After computing 392/392 offline (every previously computed value unchanged), the confident answers were
banked with `--exclude`, and each ambiguous one was then tried alone with `--only`, flipping an
environment switch between the two readings:

1. **`has_decoy_branch`** = `true` when the UTF-16LE string `decoy` appears **at any byte alignment**. In
   `d03`/`d23` the `#US` heap label sits at an odd offset, so decoding the whole buffer as UTF-16LE (even
   alignment) wrongly says `false`. (`DECOY_ALIGN`)
2. "ELF symbol-table entries with nonempty names" means **`SHT_SYMTAB` only**. For `d13`, 771 was accepted;
   `.symtab` + `.dynsym` (1255) was rejected. (`SYM_MODE`)
3. `d10` can be a **PE** (`d10--sample.exe`) even though the question says "Read ELF e_shnum". The accepted
   answer is COFF `NumberOfSections` (9), with no +1 for a null section. (`PE_SEC_PLUS`)

```python
u16 = "decoy".encode("utf-16le")
any_u16 = u16 in dll                                   # any alignment: accepted
even = dll.decode("utf-16le", "replace").find("decoy") != -1   # even alignment only: wrong for d03/d23
```

## Time Trial & Mastery
The time-trial contract was identical to single solve. `deadline: null`, no rate limiting.

| Mode | Questions | Result |
|---|---|---|
| single_solve | 392 | 389 banked, then the 3 ambiguous answers probed one by one → CORRECT |
| time_trial | 392 | 391 banked, then the `d10` PE-variant section count → CORRECT |
| mastery | 4704 (**12 sets** × 392) | CORRECT on the first submit, 18.7 s end to end (gather 9.4 s) |

Across the 12 mastery sets, `d02`, `d04` and `d10` were each ELF or PE independently; the new COFF-symbol
and PE-section code paths handled all combinations.

## Lessons / gotchas
- The contract can grow on **old** units. Read every new id from the contract diff, not only the new
  `dNN_` block.
- Implement the rule literally, then list the places where it is ambiguous (alignment, which symbol table,
  ELF wording applied to a PE) and settle each with an isolated untimed submit.
- Keep the alternative readings behind switches so probing does not require code edits.
