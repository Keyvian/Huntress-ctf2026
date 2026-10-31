"""ls28.py <artifact.bin> -- list members (CD order) with size, magic, last-bytes magic and HCFG offsets for d28."""
import sys, io, hashlib, struct
import pyzipper


def members(raw):
    z = pyzipper.AESZipFile(io.BytesIO(raw)); z.setpassword(b"infected")
    out = []
    for zi in z.infolist():
        b = z.read(zi.filename)
        if b[:2] == b"PK" and zi.filename.endswith(".zip"):
            out += [("[%s]/%s" % (zi.filename, n), x) for n, x in members(b)]
        else:
            out.append((zi.filename, b))
    return out


for n, b in members(open(sys.argv[1], "rb").read()):
    print("%-70s %9d %s" % (n, len(b), b[:8].hex()))
    if "d28" in n:
        print("   sha", hashlib.sha256(b).hexdigest(), "EI_DATA", b[5], "e_machine_le", struct.unpack("<H", b[18:20])[0],
              "e_machine_be", struct.unpack(">H", b[18:20])[0], "e_type", b[16:18].hex())
        p = b.find(b"HCFG")
        while p != -1:
            print("   HCFG @", p, "ver", b[p + 4], "key 0x%02x" % b[p + 5], "len", struct.unpack("<H", b[p + 6:p + 8])[0])
            p = b.find(b"HCFG", p + 1)
