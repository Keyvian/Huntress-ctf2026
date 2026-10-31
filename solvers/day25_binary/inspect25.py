"""Day-24 'Spot the Difference' member dump: for each d24-- jar (or any jar path given), walk every classfile
constant pool, Base64-decode every Base64-alphabet UTF-8 constant of >= 80 chars, and report each HCFG record
(version, key, length, header CRC vs computed CRC, decoded JSON). Also prints the other string constants and the
method list of each class so the vulnerable/corrected difference can be eyeballed.
usage: inspect24.py <artifact.bin|jar> [jar ...]"""
import sys, io, os, re, json, struct, base64, zlib, zipfile, hashlib
import pyzipper

B64 = re.compile(rb"^[A-Za-z0-9+/]+=*$")


def cp_entries(cb):
    p = 8
    cpc = struct.unpack(">H", cb[p:p + 2])[0]; p += 2
    cp = [None]; i = 1
    while i < cpc:
        t = cb[p]; p += 1
        if t == 1:
            l = struct.unpack(">H", cb[p:p + 2])[0]; p += 2; cp.append(("utf8", cb[p:p + l])); p += l
        elif t in (3, 4):
            cp.append((t, cb[p:p + 4])); p += 4
        elif t in (5, 6):
            cp.append((t, cb[p:p + 8])); p += 8; cp.append(None); i += 1
        elif t in (7, 8, 16, 19, 20):
            cp.append((t, struct.unpack(">H", cb[p:p + 2])[0])); p += 2
        elif t in (9, 10, 11, 12, 17, 18):
            cp.append((t, struct.unpack(">HH", cb[p:p + 4]))); p += 4
        elif t == 15:
            cp.append((t, cb[p:p + 3])); p += 3
        else:
            raise Exception("cp tag %d" % t)
        i += 1
    acc, this, sup = struct.unpack(">HHH", cb[p:p + 6]); p += 6
    ic = struct.unpack(">H", cb[p:p + 2])[0]; p += 2 + 2 * ic

    def attrs(p):
        ac = struct.unpack(">H", cb[p:p + 2])[0]; p += 2
        for _ in range(ac):
            al = struct.unpack(">I", cb[p + 2:p + 6])[0]; p += 6 + al
        return p
    fc = struct.unpack(">H", cb[p:p + 2])[0]; p += 2
    fields = []
    for _ in range(fc):
        fa, fn, fd = struct.unpack(">HHH", cb[p:p + 6]); p += 6
        fields.append((fa, cp[fn][1].decode(), cp[fd][1].decode())); p = attrs(p)
    mc = struct.unpack(">H", cb[p:p + 2])[0]; p += 2
    methods = []
    for _ in range(mc):
        ma, mn, md = struct.unpack(">HHH", cb[p:p + 6]); p += 6
        methods.append((ma, cp[mn][1].decode(), cp[md][1].decode())); p = attrs(p)
    return cp, cp[cp[this][1]][1].decode(), fields, methods


def hcfg_from_b64(s):
    d = base64.b64decode(s + b"=" * (-len(s) % 4))
    if d[:4] != b"HCFG" or len(d) < 12:
        return dict(ok=False, why="no HCFG magic", head=d[:16])
    ver, key, ln = d[4], d[5], struct.unpack("<H", d[6:8])[0]
    crc = struct.unpack("<I", d[8:12])[0]
    pl = bytes(x ^ key for x in d[12:12 + ln])
    comp = zlib.crc32(pl) & 0xffffffff
    try:
        obj = json.loads(pl.decode("utf-8"))
    except Exception as ex:
        obj = None
    return dict(ok=(comp == crc and len(d) >= 12 + ln and isinstance(obj, dict)), ver=ver, key=key, ln=ln,
                hdr_crc=crc, comp_crc=comp, total=len(d), plain=pl, cfg=obj)


def dump_jar(name, b):
    print("==", name, len(b), "B sha256", hashlib.sha256(b).hexdigest())
    jz = zipfile.ZipFile(io.BytesIO(b))
    try:
        print("  MANIFEST:", jz.read("META-INF/MANIFEST.MF").decode("latin-1").strip().replace("\n", " | "))
    except KeyError:
        pass
    for zi in jz.infolist():
        if not zi.filename.endswith(".class"):
            continue
        cb = jz.read(zi)
        cp, this, fields, methods = cp_entries(cb)
        print("  class", zi.filename, "this", this, "methods", [m[1] + m[2] for m in methods])
        print("    fields", [(f[1], f[2]) for f in fields])
        for e in cp:
            if e and e[0] == "utf8":
                s = e[1]
                if len(s) >= 80 and B64.match(s):
                    r = hcfg_from_b64(s)
                    if r.get("ok") is False and "why" in r:
                        print("    B64(%d) %s" % (len(s), r))
                    else:
                        print("    B64(%d) HCFG ver=%d key=0x%02x ln=%d hdr_crc=0x%08x comp=0x%08x ok=%s total=%d" % (
                            len(s), r["ver"], r["key"], r["ln"], r["hdr_crc"], r["comp_crc"], r["ok"], r["total"]))
                        print("      plain:", r["plain"][:300])
                elif 12 <= len(s) < 80 and not s.startswith(b"(") and b"/" not in s and b";" not in s:
                    print("    str:", s[:120])


if __name__ == "__main__":
    for path in sys.argv[1:]:
        raw = open(path, "rb").read()
        if path.endswith(".bin"):
            zf = pyzipper.AESZipFile(io.BytesIO(raw)); zf.setpassword(b"infected")
            for zi in zf.infolist():
                if os.path.basename(zi.filename).startswith("d24"):
                    dump_jar(zi.filename, zf.read(zi.filename))
        else:
            dump_jar(path, raw)
