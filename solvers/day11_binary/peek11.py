"""Inspect the d11 (D language) binary from a cached artifact dir: format, sections, HCFG candidates."""
import sys, os, re, json, io, base64, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from b10 import unzip, hcfg_blocks, b64_hcfg, sec_names, fmt_of, arch_of, machine_int
from elftools.elf.elffile import ELFFile

dd = sys.argv[1]
files = unzip(open(os.path.join(dd, sys.argv[2] if len(sys.argv) > 2 else "artifact.bin"), "rb").read())
for n, b in files:
    if not os.path.basename(n).startswith("d11"):
        continue
    print("FILE", n, len(b), fmt_of(b), arch_of(b), machine_int(b))
    print("SECS", sec_names(b))
    if b[:4] == b"\x7fELF":
        e = ELFFile(io.BytesIO(b))
        for s in e.iter_sections():
            print("  %-24s off=0x%x addr=0x%x size=0x%x" % (s.name, s["sh_offset"], s["sh_addr"], s["sh_size"]))
        c = e.get_section_by_name(".comment")
        if c: print("COMMENT", c.data()[:300])
    for m in re.finditer(rb"HCFG", b):
        print("RAW HCFG at", m.start(), b[m.start():m.start() + 16].hex())
    for m in re.finditer(rb"SENG[A-Za-z0-9+/]{8,}={0,2}", b):
        print("B64 SENG at", m.start(), m.group(0)[:80])
    for x in hcfg_blocks(b):
        print("RAWBLK", x["off"], x["ver"], x["key"], x["crc"], x["cfg"])
    for x in b64_hcfg(b):
        print("B64BLK", x["off"], x["ver"], x["key"], x["crc"], x["cfg"])
    # other encodings: hex-encoded "HCFG" = 48434647
    for m in re.finditer(rb"48434647[0-9a-fA-F]{16,}", b):
        print("HEX HCFG at", m.start(), m.group(0)[:80])
    for kw in (rb"campaign", rb"huntress", rb"Huntress", rb"day11", rb"BR11", rb"hcfg", rb"HCFG"):
        print("KW", kw, [mm.start() for mm in re.finditer(kw, b)][:10])
