"""Recursively extract a (nested, possibly WinZip-AES 'infected') zip artifact into a flat directory.
usage: unzipall.py <artifact.bin> <outdir>"""
import sys, os, io, zipfile
try:
    import pyzipper
except ImportError:
    pyzipper = None


def walk(zb, out, n=[0]):
    zf = (pyzipper.AESZipFile if pyzipper else zipfile.ZipFile)(io.BytesIO(zb))
    try:
        zf.setpassword(b"infected")
    except Exception:
        pass
    for name in zf.namelist():
        if name.endswith("/"):
            continue
        d = zf.read(name)
        if d[:2] == b"PK" and name.lower().endswith(".zip"):
            walk(d, out)
        else:
            leaf = name.split("/")[-1]
            p = os.path.join(out, leaf)
            if os.path.exists(p):
                p = os.path.join(out, "%d_%s" % (n[0], leaf)); n[0] += 1
            open(p, "wb").write(d)


os.makedirs(sys.argv[2], exist_ok=True)
walk(open(sys.argv[1], "rb").read(), sys.argv[2])
print(len(os.listdir(sys.argv[2])), "files")
