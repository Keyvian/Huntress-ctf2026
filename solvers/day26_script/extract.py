"""usage: extract.py <dir> -> extracts artifact.bin (AES, infected) into <dir>/x/"""
import sys, os, io
import pyzipper
dd = sys.argv[1]
out = os.path.join(dd, "x")
os.makedirs(out, exist_ok=True)
for f in sorted(os.listdir(dd)):
    if not (f.startswith("artifact") and f.endswith(".bin")):
        continue
    z = pyzipper.AESZipFile(io.BytesIO(open(os.path.join(dd, f), "rb").read()))
    z.setpassword(b"infected")
    for zi in z.infolist():
        if zi.filename.endswith("/"):
            continue
        b = z.read(zi.filename)
        sub = os.path.join(out, f[:-4])
        os.makedirs(sub, exist_ok=True)
        open(os.path.join(sub, os.path.basename(zi.filename)), "wb").write(b)
        if b[:2] == b"PK":
            z2 = pyzipper.AESZipFile(io.BytesIO(b)); z2.setpassword(b"infected")
            sub2 = os.path.join(sub, os.path.basename(zi.filename) + ".d")
            os.makedirs(sub2, exist_ok=True)
            for x in z2.infolist():
                if not x.filename.endswith("/"):
                    open(os.path.join(sub2, os.path.basename(x.filename)), "wb").write(z2.read(x.filename))
print("ok")
