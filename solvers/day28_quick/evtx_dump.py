"""Dissect an EVTX file (or every .evtx inside a zip): file header, chunk headers, record walk, CRC checks.
usage: evtx_dump.py <file|zip> [member-regex]"""
import sys, io, re, struct, zlib, zipfile


def dump(name, b):
    print("=" * 100)
    print(name, "len", len(b))
    h = b[:128]
    first_chunk, last_chunk, next_rec = struct.unpack_from("<QQQ", h, 8)
    hdr_size = struct.unpack_from("<I", h, 32)[0]
    minor, major, blk, nchunks = struct.unpack_from("<HHHH", h, 36)
    flags, crc = struct.unpack_from("<II", h, 120)
    print(" magic %r first_chunk %d last_chunk %d next_rec_id %d hdr_size %d ver %d.%d blk %d nchunks %d flags %d crc %08x calc %08x"
          % (h[:8], first_chunk, last_chunk, next_rec, hdr_size, major, minor, blk, nchunks, flags, crc, zlib.crc32(h[:120])))
    off = 4096
    ci = 0
    total = 0
    ids = []
    while off < len(b):
        c = b[off:off + 65536]
        if c[:8] != b"ElfChnk\0":
            print(" chunk", ci, "off", off, "len", len(c), "BAD MAGIC", c[:8])
            off += 65536; ci += 1
            continue
        f = struct.unpack_from("<QQQQIIII", c, 8)
        hcrc = struct.unpack_from("<I", c, 124)[0]
        calc_h = zlib.crc32(c[:120] + c[128:512]) if len(c) >= 512 else None
        calc_r = zlib.crc32(c[512:f[6]]) if f[6] <= len(c) and f[6] >= 512 else None
        print(" chunk %d off %d len %d first_num %d last_num %d first_id %d last_id %d hdr %d last_rec_off %d free_off %d rec_crc %08x (calc %s) hdr_crc %08x (calc %s)"
              % (ci, off, len(c), f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], ("%08x" % calc_r) if calc_r is not None else None,
                 hcrc, ("%08x" % calc_h) if calc_h is not None else None))
        p = 512
        n = 0
        while p + 24 <= len(c):
            if c[p:p + 4] != b"**\0\0":
                break
            sz = struct.unpack_from("<I", c, p + 4)[0]
            rid, ft = struct.unpack_from("<QQ", c, p + 8)
            ok = sz >= 28 and p + sz <= len(c)
            sz2 = struct.unpack_from("<I", c, p + sz - 4)[0] if ok else None
            print("   rec @%d size %d id %d filetime %d size2 %s %s" % (p, sz, rid, ft, sz2, "" if ok and sz2 == sz else "<-- BAD"))
            if not ok:
                print("   TRUNCATED record"); break
            n += 1
            ids.append(rid)
            p += sz
        tail = c[p:p + 16]
        print("  records walked %d end %d (free_off %d) tail %r" % (n, p, f[6], tail))
        ms = [m.start() for m in re.finditer(re.escape(b"**\0\0"), c)]
        print("  magic positions", ms[:60], "count", len(ms))
        total += n
        off += 65536; ci += 1
    print(" TOTAL records walked", total, "unique ids", len(set(ids)), "ids", ids[:50])


if __name__ == "__main__":
    raw = open(sys.argv[1], "rb").read()
    pat = re.compile(sys.argv[2]) if len(sys.argv) > 2 else None
    if raw[:2] == b"PK":
        z = zipfile.ZipFile(io.BytesIO(raw))
        for n in z.namelist():
            d = z.read(n)
            if d[:2] == b"PK":
                z2 = zipfile.ZipFile(io.BytesIO(d))
                for n2 in z2.namelist():
                    d2 = z2.read(n2)
                    if d2[:7] == b"ElfFile" and (not pat or pat.search(n2)):
                        dump(n + " -> " + n2, d2)
                    elif not pat:
                        print("MEMBER", n, "->", n2, len(d2), d2[:40])
            elif d[:7] == b"ElfFile" and (not pat or pat.search(n)):
                dump(n, d)
            elif not pat:
                print("MEMBER", n, len(d), d[:40])
                if n.endswith((".txt", ".md", ".json", ".csv")):
                    print(d.decode("utf-8", "replace")[:1200])
    else:
        dump(sys.argv[1], raw)
