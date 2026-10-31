"""peek31.py <artifact.bin> -- static look at the d31 member: header, sections, tail, every HGAU candidate."""
import sys, io, json, zlib, struct, re, hashlib
import pyzipper
from elftools.elf.elffile import ELFFile

z = pyzipper.AESZipFile(io.BytesIO(open(sys.argv[1], "rb").read()))
z.setpassword(b"infected")
names = [i.filename for i in z.infolist() if i.filename.startswith("d31--")]
print(names)
b = z.read(names[0])
print("len", len(b), "magic", b[:8], "sha256", hashlib.sha256(b).hexdigest())
e = ELFFile(io.BytesIO(b))
print({k: e.header[k] for k in ("e_type", "e_machine", "e_entry", "e_shoff", "e_shnum", "e_phnum")}, "class", e.elfclass)
end = 0
for s in e.iter_sections():
    print("  %-22s %-14s addr=%#x off=%#x size=%#x" % (s.name, s["sh_type"], s["sh_addr"], s["sh_offset"], s["sh_size"]))
    if s["sh_type"] != "SHT_NOBITS":
        end = max(end, s["sh_offset"] + s["sh_size"])
shend = e.header["e_shoff"] + e.header["e_shnum"] * e.header["e_shentsize"]
print("sections end", hex(end), "sht end", hex(shend), "file", hex(len(b)), "overlay", len(b) - max(end, shend))
for magic in (b"HGAU", b"HCFG", b"HGRF", b"RS20", b"PK19"):
    print(magic, [m.start() for m in re.finditer(magic, b)][:20])
p = b.rfind(b"HGAU")
while p != -1:
    if p + 12 <= len(b):
        ver, key = b[p + 4], b[p + 5]
        size = struct.unpack("<H", b[p + 6:p + 8])[0]
        crc = struct.unpack("<I", b[p + 8:p + 12])[0]
        plain = bytes(c ^ key for c in b[p + 12:p + 12 + size])
        ok = zlib.crc32(plain) & 0xffffffff == crc
        print("cand", p, "ver", ver, "key", hex(key), "size", size, "crc", hex(crc), "ok", ok,
              "bounds", p + 12 + size <= len(b))
        if ok:
            print(plain.decode("utf-8", "replace")[:3000])
    p = b.rfind(b"HGAU", 0, p)
print("tail", b[-96:])
