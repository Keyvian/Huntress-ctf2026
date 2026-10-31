# 🔎 Packet Loss Prevention

| | |
|---|---|
| **Day** | 27 |
| **Lane** | 🔎 Metadata Forensics |
| **Challenge ID** | `metadata-forensics-day-27-packet-loss-prevention` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day27_quick/m27.py`](../solvers/day27_quick/m27.py) + capture parser [`pcap.py`](../solvers/day27_quick/pcap.py) |

## Prompt
> Packet captures, exports, and host artifacts describe the same incident from different angles. Count traffic, reject malformed captures, and find the host narrative missing network evidence.

## TL;DR
The new field is `pcap.packet_count` for `capture-001.pcap`: the number of complete packet records in a classic
libpcap file, counted by walking the 16-byte record headers. Variant 000 has 3 records. Captured-length shorter than
original-length (snaplen truncation) still counts as a packet. No malformed capture appeared in any of the 13 files seen.

## Artifact
- Variant 000: 119 bytes, classic little-endian microsecond pcap v2.4, linktype 147 (`USER0`), snaplen 65535, three
  records: 16 bytes `00..0f`, the string `huntress-a13d4ebca69c`, and `PCAP-PROOF` with `incl_len 10 < orig_len 64`.
  The answer is **3**.
- Time-trial and mastery variants: classic LE v2.4, linktypes 1 / 101 / 105, snaplen 32768 / 65535 / 65536 / 262144,
  7–37 records with random payloads, some truncated (`incl < orig`). `pcap.py` reported zero errors on all of them.
- Answer id `d27-pcap-001-pcap-packet-count`.
- Time Trial: **32 questions**. Mastery: **11 sets × 32 = 352**. The synthesis question now lists `capture-001.pcap`
  among six files.

## Solution
```python
magic = b[:4]
en = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",          # microsecond
      b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}[magic]   # nanosecond
p, n = 24, 0                                   # 24-byte global header
while p + 16 <= len(b):
    ts_sec, ts_frac, incl, orig = struct.unpack_from(en + "IIII", b, p)
    if p + 16 + incl > len(b):                 # record runs past EOF -> not complete
        break
    n += 1
    p += 16 + incl                             # advance by the CAPTURED length
answer = str(n)
```

The key detail is advancing by `incl_len` (bytes actually stored), not `orig_len` (bytes on the wire).

`pcap.py` handles all four classic magics and pcapng (SHB / IDB / EPB / SPB / OPB blocks) with strict validation:
bad magic, record past EOF, `incl > snaplen`, `incl > orig`, and so on. Each problem appears in the `PCAP …` line
`m27.py` prints per capture, so a malformed variant would be visible before the submit. It also reports captured bytes,
the truncated-packet count, the maximum packet length, linktype and timestamps.

## Time Trial & Mastery
Regular untimed attempts. `m27.py <id> start --save dir` computes without submitting, then
`m27.py <id> none --dir dir --submit` submits the reviewed answers. Single CORRECT, Time Trial CORRECT 32/32 one-shot,
Mastery CORRECT 352/352. The whole quick lane took about 6 minutes; only metadata needed new code.

## Lessons / gotchas
- Packets truncated by snaplen are still packets. "Reject malformed captures" means structural damage, such as a
  record running past the end of the file, not short captures.
- The pattern held again: one honest field per new file type, despite the forensic-story prompt. The parser is still
  built in full, with diagnostics.
