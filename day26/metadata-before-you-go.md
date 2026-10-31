# 🔎 Before You Go

| | |
|---|---|
| **Day** | 26 |
| **Lane** | 🔎 Metadata Forensics |
| **Challenge ID** | `metadata-forensics-day-26-before-you-go` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day26_quick/m26.py`](../solvers/day26_quick/m26.py) + Prefetch parser / decompressor [`prefetch.py`](../solvers/day26_quick/prefetch.py) |

## Prompt
> Prefetch evidence records what Windows prepared to execute even after filenames changed. Recover executable identities and connect execution traces to the correct hosts.

## TL;DR
The new field is `prefetch.executable_name` for `trace-001.pf`: the UTF-16LE executable name stored at offset 16 of the
`SCCA` prefetch header. The on-disk name `trace-001.pf` is a renamed decoy. Variant 000 was a Windows 10
`MAM\x04` file, compressed with LZXPRESS Huffman, so the agent wrote a pure-Python MS-XCA decompressor before the
header could even be read. It yielded `CMD.EXE`.

## Artifact
- `trace-001.pf`, answer id `d26-prefetch-001-prefetch-executable-name`.
- Variant 000 (single): `MAM\x04` header, 3,896 bytes compressed → 15,412 bytes decompressed → `CMD.EXE`.
- Every time-trial and mastery variant seen was an **uncompressed** version-30 `SCCA` file, with names such as
  `OBSIDIAN4.EXE`, `PACKAGER.EXE`, `SESSIONHOST.EXE`, `LAUNCHER.EXE`, `MAILCLIENT.EXE`, `ATLAS19.EXE`, `HELPER.EXE`.
- "Connect execution traces to the correct hosts" never became a question.
- Time Trial: **31 questions**. Mastery: **10 sets × 31 = 310**. The synthesis question now includes `trace-001.pf`.

## Solution
1. **Decompress if needed.** Windows 10+ prefetch files start with `MAM` + `\x04` (LZXPRESS Huffman; `\x84` adds a
   CRC-32), then the u32 decompressed size. The format is MS-XCA §2.2.4: 64 KiB output chunks, each preceded by a
   256-byte table of 512 4-bit code lengths, then a canonical Huffman code (max 15 bits). Symbols below 256 are
   literals. Symbols 256–511 encode a match: the low 4 bits give the length (15 = read extension bytes), the high bits
   give the number of offset bits. `prefetch.py` follows the spec's order (length-extension bytes first, then the
   offset bits). If that output does not start with `SCCA`, it retries with the opposite order.
2. **Parse the SCCA header**: version (u32 at 0: 17 XP, 23 Vista/7, 26 8.1, 30 Win10/11), `SCCA` at 4, file size at 12,
   the executable name at **16** (60 bytes, UTF-16LE, NUL-terminated), the prefetch hash at 76.

```python
d, compressed = prefetch.decompress_mam(b)    # returned unchanged if not MAM-compressed
assert d[4:8] == b"SCCA"
name = d[16:76].decode("utf-16-le").split("\x00", 1)[0]   # "CMD.EXE"
```

`prefetch.py` also parses the version 17/23/26/30 file-information blocks: run count (the v30 metrics offset
differs, 300 vs 308), the eight last-run times, volumes (device path, creation time, serial), the filename-string
table (35 entries per file) and the full executable path. That is about 20 fields with aliases.
`prefetch.py <file.pf> [field…]` dumps them.

## Time Trial & Mastery
Regular untimed attempts. The listing advertised metadata ranked budgets of 50 s and 325 s. Single CORRECT,
Time Trial CORRECT 31/31 one-shot, Mastery CORRECT 310/310. `m26.py` prints a `PF …` diagnostic line per file.

## Lessons / gotchas
- The prefetch file's own name (`<EXE>-<HASH>.pf` on a real system) is just a label. The executable name inside the
  header survives renaming, which is the prompt's point.
- Only the single was compressed. Solving the single first is what forced the decompressor to exist. A solver
  written against the timed variants alone would have failed on the first `MAM` file it met.
