"""Day-31 quick peek: warm blob layers, metadata nested zip tree (+manifest, text members), mobile APK listing + puzzle.
usage: peek31.py warm <file> | meta <file> | mob <file>"""
import sys, io, json, base64, gzip, zlib, zipfile, hashlib, re
import pyzipper


def tree(b, pfx="", depth=0):
    z = pyzipper.AESZipFile(io.BytesIO(b))
    z.setpassword(b"infected")
    for zi in z.infolist():
        if zi.filename.endswith("/"):
            continue
        try:
            d = z.read(zi.filename)
        except Exception as ex:
            print(" " * depth, pfx + zi.filename, "UNREADABLE", repr(ex)[:80])
            continue
        print(" " * depth, pfx + zi.filename, len(d), hashlib.sha256(d).hexdigest()[:12], d[:16], "date", zi.date_time, "cmt", zi.comment[:40], "ct", zi.compress_type)
        if d[:4] == b"PK\x03\x04":
            tree(d, pfx + zi.filename + "/", depth + 1)
        elif len(d) < 3000 and all(c in b"\r\n\t" or 32 <= c < 127 for c in d):
            print(d.decode("latin1"))


def main():
    what, fn = sys.argv[1], sys.argv[2]
    b = open(fn, "rb").read()
    if what == "warm":
        d = base64.b64decode(b)
        print("gz", d[:12])
        p = gzip.decompress(d)
        print(p[:600])
        print(p.decode("latin1"))
    elif what == "meta":
        tree(b)
    elif what == "mob":
        z = zipfile.ZipFile(io.BytesIO(b))
        for zi in z.infolist():
            print(zi.filename, zi.file_size, zi.compress_type)
        for n in z.namelist():
            if n.endswith(".json"):
                print(n, z.read(n)[:1500])


main()
