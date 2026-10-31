"""Inspect the d22 members of a cached evidence.zip: dnfile metadata, HCFG scan, machine field."""
import sys, io, json, struct, zlib, hashlib, re, os
sys.path.insert(0, "~/ctf")
import pyzipper, dnfile

d = sys.argv[1]
raw = open(os.path.join(d, "artifact.bin"), "rb").read()
zf = pyzipper.AESZipFile(io.BytesIO(raw)); zf.setpassword(b"infected")
fl = [(zi.filename, zf.read(zi.filename)) for zi in zf.infolist() if zi.filename.startswith("d22")]
for n, b in fl:
    print(n, len(b), hashlib.sha256(b).hexdigest(), b[:4])
    open(os.path.join(d, n), "wb").write(b)


def hcfg_all(b):
    out = []; p = b.find(b"HCFG")
    while p != -1:
        if p + 12 <= len(b):
            ver, key, size = b[p + 4], b[p + 5], struct.unpack("<H", b[p + 6:p + 8])[0]
            hdr = struct.unpack("<I", b[p + 8:p + 12])[0]
            plain = bytes(x ^ key for x in b[p + 12:p + 12 + size])
            ok_b = p + 12 + size <= len(b)
            crc = zlib.crc32(plain) & 0xffffffff
            try:
                obj = json.loads(plain.decode()); ok_j = isinstance(obj, dict)
            except Exception:
                obj = None; ok_j = False
            out.append(dict(off=p, ver=ver, key=key, size=size, hdr=hex(hdr), crc=hex(crc), ok=ok_b and crc == hdr and ok_j, cfg=obj))
        p = b.find(b"HCFG", p + 1)
    return out


for n, b in fl:
    if b[:2] == b"MZ":
        pe = dnfile.dnPE(data=b)
        print("==", n, "machine=0x%x" % pe.FILE_HEADER.Machine, "net=", pe.net is not None)
        if pe.net:
            print(" mdver=", pe.net.metadata.struct.Version)
        hs = hcfg_all(b)
        print(" HCFG hits:", [(h["off"], h["ver"], h["key"], h["size"], h["hdr"], h["crc"], h["ok"]) for h in hs])
        for h in hs:
            if h["ok"]:
                print("  CFG", json.dumps(h["cfg"]))
        print(" SENG raw:", len(re.findall(rb"SENG[A-Za-z0-9+/]{16,}", b)),
              " SENG u16:", len(re.findall(rb"SENG[A-Za-z0-9+/]{16,}", b.replace(b"\x00", b""))))
        print(" HCFG in u16-stripped:", len(hcfg_all(b.replace(b"\x00", b""))))
        secs = [s.Name.rstrip(b"\x00").decode() for s in pe.sections]
        print(" sections:", secs)
        try:
            imps = [e.dll.decode() for e in pe.DIRECTORY_ENTRY_IMPORT] if hasattr(pe, "DIRECTORY_ENTRY_IMPORT") else []
            print(" imports:", imps)
        except Exception as ex:
            print(" imports err", ex)
        if pe.net and pe.net.mdtables:
            mt = pe.net.mdtables
            if mt.ImplMap:
                print(" ImplMap rows:", [(r.ImportName, r.ImportScope.row.Name if r.ImportScope and r.ImportScope.row else None) for r in mt.ImplMap])
            if mt.ModuleRef:
                print(" ModuleRef:", [r.Name for r in mt.ModuleRef])
            if mt.TypeDef:
                print(" TypeDefs:", [r.TypeName for r in mt.TypeDef][:40])
            if mt.FieldRva:
                print(" FieldRVA:", [(r.Rva, r.Field.row.Name if r.Field and r.Field.row else None) for r in mt.FieldRva])
    else:
        print("==", n, b[:200])
