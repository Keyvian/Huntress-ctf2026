"""survey31.py -- static survey of every saved d31 member (never run): which record keys, branches, config equality."""
import sys, io, os, re, json, zlib, struct
import pyzipper

D = "~/d31"
files = [("single", D + "/bin_s/artifact.bin"), ("tt", D + "/bin_tt/artifact.bin")]
for f in sorted(os.listdir(D + "/bin_m")):
    if re.fullmatch(r"artifact(_d\d+)?\.bin", f):
        files.append(("m:" + f, D + "/bin_m/" + f))
for tag, p in files:
    z = pyzipper.AESZipFile(io.BytesIO(open(p, "rb").read()))
    z.setpassword(b"infected")
    names = [i.filename for i in z.infolist() if os.path.basename(i.filename).startswith("d31")]
    b = z.read(names[0])
    good = []
    q = b.rfind(b"HGAU")
    n = 0
    while q != -1:
        n += 1
        k = b[q + 5]
        size = struct.unpack("<H", b[q + 6:q + 8])[0]
        crc = struct.unpack("<I", b[q + 8:q + 12])[0]
        pl = bytes(c ^ k for c in b[q + 12:q + 12 + size])
        if q + 12 + size <= len(b) and zlib.crc32(pl) & 0xffffffff == crc:
            good.append((q, json.loads(pl)))
        q = b.rfind(b"HGAU", 0, q)
    o = good[0][1]
    print(tag, names, "len", len(b), "cands", n, "good", len(good), "off", good[0][0], "trailing", len(b) - good[0][0],
          "keys", sorted(o), "variant", o.get("variant"), "trace", o.get("trace"), "langs", len(o.get("languages", [])))
