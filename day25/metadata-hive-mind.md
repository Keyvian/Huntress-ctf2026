# 🔎 Hive Mind

| | |
|---|---|
| **Day** | 25 |
| **Lane** | 🔎 Metadata Forensics |
| **Challenge ID** | `metadata-forensics-day-25-hive-mind` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day25_quick/m25.py`](../solvers/day25_quick/m25.py) + registry hive parser [`reghive.py`](../solvers/day25_quick/reghive.py) |

## Prompt
> Registry hives from multiple systems have been renamed and separated from host labels. Identify each true root, regroup the systems, and isolate the planted hive.

## TL;DR
The new field is `registry.hive_root_name` for `hive-001.hiv`: the key name stored in the hive's **root `nk` cell**,
reached through `root_cell_offset` in the `regf` base block. The trap is a second, plausible name in the same header.
The base block embeds a file name (UTF-16LE at offset 48), and that is the *renamed* on-disk label the prompt warns
about, not the root.

## Artifact
- `hive-001.hiv`: `regf` magic, 8,192 bytes, made of a 4 KiB base block plus one 4 KiB `hbin`. One key, two values.
- Answer id `d25-registry-001-registry-hive-root-name`.
- Variant 000 root: `HuntressArtifactAssemblyLine`. Time-trial and mastery roots are random alphanumerics (e.g.
  `XSoDveGTJ`, `JmfdRxNU`).
- The embedded header names hold the last 31 characters of a path, e.g. `ress-artifact-assembly-line.hiv` or
  `tundra-ce71b32e.hiv`. They never equal the root name.
- Root values: `Marker` (REG_SZ: `HUNTRESS-HIVE-4203` on 000, an 18-hex string on the variants) and `Ordinal`
  (REG_DWORD 4203, identical on all 11 hives seen). Header checksums were all valid and the sequence numbers matched.
  "Regroup the systems / isolate the planted hive" never became a question.
- Time Trial: **30 questions**. Mastery: **9 sets × 30 = 270**. The synthesis question now includes `hive-001.hiv`.

## Solution
```python
assert b[:4] == b"regf"
root_off = struct.unpack_from("<I", b, 0x24)[0]     # relative to the first hbin (file offset 0x1000)
cell = 0x1000 + root_off                             # here 0x20 -> 0x1020
size = struct.unpack_from("<i", b, cell)[0]          # negative = allocated cell
nk = b[cell + 4:]
assert nk[:2] == b"nk"
flags = struct.unpack_from("<H", nk, 2)[0]           # 0x002c = HIVE_ENTRY | NO_DELETE | COMP_NAME
name_len = struct.unpack_from("<H", nk, 0x48)[0]
name = nk[0x4c:0x4c + name_len]
answer = name.decode("latin-1" if flags & 0x20 else "utf-16-le")   # COMP_NAME = 1 byte per char
```

- The base block stores `root_cell_offset` relative to the start of the hive bins (file offset `0x1000`).
- A cell begins with a signed 32-bit size (negative when allocated), then the `nk` record.
- `KEY_COMP_NAME` (`0x0020`) means the name is stored one byte per character. Otherwise it is UTF-16LE.

`reghive.py` is a broader parser. It covers the base block (sequence numbers, timestamps, version, root offset, bins
size, embedded name, GUIDs, XOR-32 checksum), hbins, cells (`nk` / `vk` / `sk`, `lf` / `lh` / `li` / `ri` subkey
lists, `db` big data), a key-tree walk and value decoding. It exposes about 80 fields with aliases (`hive_root_name`,
`header_file_name`, `root_value_marker`, `checksum_valid`, `key_count`, …). `m25.py` prints a `REGF …` line per hive
(root, header name, checksum, bins, key and value counts, root values) before submitting.

## Time Trial & Mastery
All timed modes were regular untimed attempts. The listing now advertises ranked budgets (metadata 50 s time trial,
295 s mastery) but the regular play still scores. Single CORRECT, Time Trial CORRECT 30/30 one-shot, Mastery CORRECT
270/270.

## Lessons / gotchas
- Two names live in a hive header area. The base-block file name is whatever the file was called when it was last
  saved; it is a label, and labels in this lane lie. The root key name is structural.
- Offsets in `regf` are relative to `0x1000`. Forgetting the base-block size lands in the middle of the header.
