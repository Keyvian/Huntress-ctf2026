"""zls.py <zipfile> : recursively list a zip (in memory) with sizes + magic."""
import sys, io, zipfile
try:
    import pyzipper
except Exception:
    pyzipper = None

def walk(b, pfx=""):
    Z = pyzipper.AESZipFile if pyzipper else zipfile.ZipFile
    z = Z(io.BytesIO(b))
    try: z.setpassword(b"infected")
    except Exception: pass
    for i in z.infolist():
        d = z.read(i.filename)
        print("%s%s  size=%d  magic=%r" % (pfx, i.filename, len(d), d[:16]))
        if d[:2] == b"PK":
            walk(d, pfx + i.filename + " -> ")
        elif len(d) < 3000 and not d[:2] in (b"MZ", b"\x7fE"):
            print("   ", d[:3000].decode("utf-8", "replace").replace("\n", "\n    "))

walk(open(sys.argv[1], "rb").read())
