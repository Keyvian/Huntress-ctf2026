"""Day-31 peek: locate every case-*.zip inside an evidence zip (any depth) and dump it with peek31b's dumper.
usage: peek31c.py <evidence.zip> [outdir]"""
import sys, io, os
sys.argv_saved = sys.argv[:]
import pyzipper


def walk(b, pfx=""):
    z = pyzipper.AESZipFile(io.BytesIO(b))
    z.setpassword(b"infected")
    for zi in z.infolist():
        if zi.filename.endswith("/"):
            continue
        try:
            d = z.read(zi.filename)
        except Exception as ex:
            print("UNREADABLE", pfx + zi.filename, repr(ex)[:80])
            continue
        name = pfx + zi.filename
        base = os.path.basename(zi.filename)
        if d[:4] == b"PK\x03\x04":
            if base.startswith("case-"):
                yield name, d
            elif base.startswith("cluster-"):
                pass
            elif not base.endswith((".apk", ".jar", ".docx", ".xlsx", ".pptx")):
                yield from walk(d, name + "/")


b = open(sys.argv[1], "rb").read()
out = sys.argv[2] if len(sys.argv) > 2 else "/tmp/d31cases"
os.makedirs(out, exist_ok=True)
for i, (n, d) in enumerate(walk(b)):
    fn = os.path.join(out, "c%02d_%s" % (i, os.path.basename(n)))
    open(fn, "wb").write(d)
    print(n, len(d), "->", fn)
