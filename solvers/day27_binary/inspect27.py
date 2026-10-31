"""inspect27.py <artifact.bin|evidence.zip> -- dump the d27-- members: names (CD order), size, ELF header,
every literal HCFG occurrence (forward order) with its verdict, plus a few toolchain fingerprints."""
import sys, io, json, zlib, struct, hashlib, re
import pyzipper


def members(raw):
    z = pyzipper.AESZipFile(io.BytesIO(raw)); z.setpassword(b"infected")
    out = []
    for zi in z.infolist():
        b = z.read(zi.filename)
        if b[:2] == b"PK" and zi.filename.endswith(".zip"):
            out += members(b)
        else:
            out.append((zi.filename, b))
    return out


for n, b in members(open(sys.argv[1], "rb").read()):
    if not n.split("/")[-1].startswith("d27"):
        continue
    print("==", n, len(b), hashlib.sha256(b).hexdigest())
    print("   magic", b[:4], "class", b[4], "data", b[5], "e_type", struct.unpack("<H", b[16:18])[0],
          "e_machine", struct.unpack("<H", b[18:20])[0])
    p = b.find(b"HCFG")
    while p != -1:
        ver, key, size = b[p + 4], b[p + 5], struct.unpack("<H", b[p + 6:p + 8])[0]
        crc = struct.unpack("<I", b[p + 8:p + 12])[0]
        plain = bytes(c ^ key for c in b[p + 12:p + 12 + size])
        ok = zlib.crc32(plain) & 0xffffffff == crc
        try:
            j = json.loads(plain.decode())
        except Exception:
            j = None
        print("   HCFG @%d ver=%d key=0x%02x size=%d crc_ok=%s json=%s" % (p, ver, key, size, ok,
              json.dumps(j)[:300] if j is not None else None))
        p = b.find(b"HCFG", p + 1)
    for pat in (rb"GCC: \([^\x00]{0,80}", rb"tcc[^\x00]{0,40}", rb"\.comment", rb"\.note\.gnu\.build-id",
                rb"\.gnu\.version", rb"ld-linux[^\x00]{0,30}", rb"GLIBC_[0-9.]+"):
        ms = sorted(set(m.group(0)[:90] for m in re.finditer(pat, b)))
        if ms:
            print("   ", pat.decode(errors="replace"), ms[:6])
