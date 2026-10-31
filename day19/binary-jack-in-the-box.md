# ⚙️ Jack in the Box

| | |
|---|---|
| **Day** | 19 |
| **Lane** | ⚙️ Binary Reverse Engineering |
| **Challenge ID** | `binary-reverse-engineering-day-19-static-unpacking` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | `b19.py` was not preserved; its `d19_fields()` is carried verbatim in [`solvers/day20_binary/b20.py`](../solvers/day20_binary/b20.py) |

## Prompt
> There's a payload hiding inside this binary, and a little decoder stub wound up to pop it out. Find the stub, watch it work, and catch what's inside — statically.

## TL;DR
Day-18 contract plus a 12-question `d19` unit: a GnuCOBOL ELF with a **packed overlay** appended after the
section-header table. The overlay header (`PK19`) carries two byte keys, a length and the SHA-256 of the
unpacked data; each byte unpacks as `ror8(b ^ k2, 3) ^ k1`, and the result is an ordinary HCFG record. The
question text described the overlay layout and the transform exactly, so no disassembly of the stub was
needed. All three modes passed on the first submit.

## Artifact
WinZip-AES ZIP (password `infected`). New member `d19--variant-NNN.elf`: 11,232 bytes, stripped, dynamically
linked against `libcob.so.1`, program id `BR19`, source name `variant-000.cob`. Its section headers end at
9080 + 27 × 64 = 10808; the remaining 424 bytes are the overlay.

New fields: `d19_artifact_sha256_1`, `d19_analysis_{format,architecture,machine}`,
`d19_analysis_config_{campaign,domain,mutex,url,crc32_hex}`, `d19_analysis_hcfg_version`, and two new kinds,
**`d19_analysis_overlay_offset`** and **`d19_analysis_overlay_size`**.

## Solution
The overlay format, as the question spelled it out:

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `PK19` |
| 4 | 1 | version |
| 5 | 1 | `k1` |
| 6 | 1 | `k2` |
| 8 | 4 | packed length, u32le |
| 12 | 32 | SHA-256 of the unpacked bytes |
| 44 | n | packed bytes |

```python
def ror8(x, n):
    return ((x >> n) | (x << (8 - n))) & 0xff

o = offs[-1]                                   # the FINAL PK19 occurrence in the member
k1, k2 = b[o + 5], b[o + 6]
plen = struct.unpack("<I", b[o + 8:o + 12])[0]
un = bytes(ror8(x ^ k2, 3) ^ k1 for x in b[o + 44:o + 44 + plen])
assert hashlib.sha256(un).digest() == b[o + 12:o + 44]
blk = hcfg_blocks(un)                          # HCFG record at unpacked offset 0
```

- `overlay_offset` = zero-based offset of the **final** `PK19` magic in the member (10808).
- `overlay_size` = member length minus that offset (424).
- `config_crc32_hex` = the HCFG header's own bytes 8–11 as `0x%08x` (equal to the computed CRC32 when the
  record is valid).
- The unpacked HCFG record (version 1, one-byte XOR key, LE16 length 368) decodes with the existing parser.
- `format` `elf`, `architecture` `x86-64`, `machine` `62`, `hcfg_version` `1`.

Across the variants seen (single, time trial and the mastery sets), `k1` was 0x21–0x28, `k2` 0x9d–0xa4, the
packed length always 380, and the SHA-256 and CRC32 always verified. Only one `PK19` occurrence existed per
binary. A plaintext JSON trace in `.rodata` (`family: cobol_static_unpack_trace`,
`effects: memory_only_inert_payload_hash`) is a distractor.

## Time Trial & Mastery
Both timed modes returned `deadline: None` and graded normally.

| Mode | Questions | Time used |
|---|---|---|
| single_solve | 228 | untimed, one submit |
| time_trial | 228 | 4.8 s end to end |
| mastery | 1140 (5 sets × 228) | 12.2 s end to end; each delivery ~33 MB, gathered in parallel in ~9 s |

## Lessons / gotchas
- From this point the new questions describe their container layout precisely ("magic `PK19` at +0,
  version at +4 …"). Read the question text first and implement it literally.
- Use the last magic occurrence, as specified, even when only one exists; it protects against an earlier
  decoy.
- Verify the embedded hash after unpacking: it proves the transform before you submit anything.
- The question wording mentioned "PK19 for Day 19 or RS20 for Day 20", which predicted the next day's
  overlay format.
