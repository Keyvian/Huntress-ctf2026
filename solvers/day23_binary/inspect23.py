"""Standalone dump of the d23 members in a cached artifact: HCFG hits (valid/decoy), PE/CLR facts, strings, tables.
usage: inspect_d23.py <artifact.bin> [prefix=d23--]"""
import sys, io, json, struct, zlib, hashlib, re
import pyzipper, dnfile

raw = open(sys.argv[1], "rb").read()
pfx = sys.argv[2] if len(sys.argv) > 2 else "d23--"
zf = pyzipper.AESZipFile(io.BytesIO(raw)); zf.setpassword(b"infected")
mem = [(zi.filename, zf.read(zi.filename)) for zi in zf.infolist() if zi.filename.startswith(pfx)]
for n, b in mem:
    print("MEMBER", n, len(b), hashlib.sha256(b).hexdigest(), b[:4])
dll = next(b for n, b in mem if n.endswith(".dll"))
rc = next((b for n, b in mem if n.endswith(".runtimeconfig.json")), b"")
print("RUNTIMECONFIG", rc.decode("utf-8", "replace"))
pe = dnfile.dnPE(data=dll)
print("Machine 0x%04x" % pe.FILE_HEADER.Machine, "net?", pe.net is not None)
if pe.net:
    print("metadata version", pe.net.metadata.struct.Version)
p = dll.find(b"BSJB"); ln = struct.unpack("<I", dll[p + 12:p + 16])[0]
print("BSJB at", p, "len", ln, dll[p + 16:p + 16 + ln])
print("sections", [(s.Name.rstrip(b"\x00").decode(), s.PointerToRawData, s.SizeOfRawData) for s in pe.sections])
p = dll.find(b"HCFG"); n = 0
while p != -1:
    n += 1
    ver, key, size = dll[p + 4], dll[p + 5], struct.unpack("<H", dll[p + 6:p + 8])[0]
    hdr = struct.unpack("<I", dll[p + 8:p + 12])[0]
    inb = p + 12 + size <= len(dll)
    plain = bytes(x ^ key for x in dll[p + 12:p + 12 + size]) if inb else b""
    crc = zlib.crc32(plain) & 0xffffffff
    ok_json = False; obj = None
    try:
        obj = json.loads(plain.decode("utf-8")); ok_json = isinstance(obj, dict)
    except Exception:
        pass
    print("HCFG@%d ver=%d key=0x%02x size=%d hdr_crc=0x%08x crc=0x%08x inb=%s crc_ok=%s json_ok=%s" % (
        p, ver, key, size, hdr, crc, inb, crc == hdr, ok_json), (obj if ok_json else plain[:60]))
    p = dll.find(b"HCFG", p + 1)
print("n HCFG hits", n)
print("utf16 HCFG at", dll.find("HCFG".encode("utf-16-le")))
print("SENG b64 hits", [m.start() for m in re.finditer(rb"SENG[A-Za-z0-9+/]{16,}", dll)])
strs = re.findall(rb"[\x20-\x7e]{6,}", dll)
kw = [s for s in strs if re.search(rb"(?i)debug|tick|clock|time|env|sandbox|vm|analy|watch|trust|predicate|truth|branch|check|sniff|hcfg|xor|key", s)]
print("INTERESTING STRINGS", [s.decode() for s in kw][:80])
u16 = re.findall(rb"(?:[\x20-\x7e]\x00){6,}", dll)
print("UTF16 STRINGS", [s.decode("utf-16-le") for s in u16][:80])
try:
    mt = pe.net.mdtables
    print("TypeDefs", [str(r.TypeName) for r in mt.TypeDef])
    print("Methods", [str(r.Name) for r in mt.MethodDef][:120])
    if mt.ImplMap:
        print("PInvoke", [(str(r.ImportName), str(r.ImportScope.row.Name)) for r in mt.ImplMap])
    print("MemberRefs", [str(r.Name) for r in mt.MemberRef][:120])
    print("Fields", [str(r.Name) for r in mt.Field][:80])
except Exception as e:
    print("mt err", e)
