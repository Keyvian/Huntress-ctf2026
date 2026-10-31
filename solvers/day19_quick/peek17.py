"""Inspect the Day-17 quick artifacts saved under ~/d17q/{warm,meta,mob}_s (read-only; nothing is executed).
usage: peek17.py <root dir>"""
import sys, os, zipfile, struct, json, io

root = sys.argv[1]


def riff(b):
    print("  RIFF hdr", b[:12])
    off = 12
    while off + 8 <= len(b):
        cid = b[off:off + 4]
        sz = struct.unpack("<I", b[off + 4:off + 8])[0]
        body = b[off + 8:off + 8 + sz]
        if cid == b"fmt ":
            tag, ch, sr, br, ba, bps = struct.unpack("<HHIIHH", body[:16])
            print("  fmt  tag=%d(0x%x) ch=%d sr=%d byterate=%d align=%d bps=%d extra=%s" % (tag, tag, ch, sr, br, ba, bps, body[16:].hex()))
        elif cid == b"data":
            print("  data size=%d first=%s" % (sz, body[:16].hex()))
        else:
            print("  chunk", cid, sz, body[:80])
        off += 8 + sz + (sz & 1)


p = os.path.join(root, "warm_s", "artifact.bin")
if os.path.exists(p):
    b = open(p, "rb").read()
    print("== WARM", len(b))
    s = b.decode("latin1")
    for i in range(0, min(len(s), 1400), 120):
        print("  ", s[i:i + 120])
    print("  charset", sorted(set(s)))

p = os.path.join(root, "meta_s", "artifact.bin")
if os.path.exists(p):
    z = zipfile.ZipFile(p)
    print("== META")
    for n in z.namelist():
        b = z.read(n)
        print(" ", n, len(b), b[:4])
        if b[:4] == b"RIFF":
            riff(b)
        else:
            print("  head", b[:96].hex())

p = os.path.join(root, "mob_s", "artifact.bin")
if os.path.exists(p):
    z = zipfile.ZipFile(p)
    print("== MOB")
    for zi in z.infolist():
        print(" ", zi.filename, zi.file_size)
    print(z.read("assets/huntress_puzzle.json").decode("utf-8", "replace"))
    dex = z.read("classes.dex")
    strs = []
    cur = b""
    for c in dex:
        if 32 <= c < 127:
            cur += bytes([c])
        else:
            if len(cur) >= 4:
                strs.append(cur.decode())
            cur = b""
    print("  dex strings:", strs)
    man = z.read("AndroidManifest.xml")
    ms = []
    cur = b""
    for i in range(0, len(man) - 1, 2):
        c = man[i]
        if man[i + 1] == 0 and 32 <= c < 127:
            cur += bytes([c])
        else:
            if len(cur) >= 4:
                ms.append(cur.decode())
            cur = b""
    print("  manifest utf16 strings:", ms)
