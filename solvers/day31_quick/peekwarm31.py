"""Day-31 warmup mastery peek: unpack the bundle, list row counts and the last rows' decode via Day-31 base64 -> gunzip -> base32.
usage: peekwarm31.py <artifact.bin> <start.json>"""
import sys, io, json, zipfile, gzip, zlib, base64, collections, re

blobs = {}


def walk(zb):
    z = zipfile.ZipFile(io.BytesIO(zb))
    for n in z.namelist():
        b = z.read(n)
        if b[:2] == b"PK":
            walk(b)
        else:
            blobs[n.split("/")[-1]] = b


walk(open(sys.argv[1], "rb").read())
print("blobs", len(blobs), list(blobs)[:3])
st = json.load(open(sys.argv[2]))
print("q0", json.dumps(st["questions"][0])[:400])
print("q-1", json.dumps(st["questions"][-1])[:400])
c = collections.Counter()
for i, (n, b) in enumerate(sorted(blobs.items())):
    rows = [l for l in b.decode("utf-8", "replace").splitlines() if l.strip()]
    c[len(rows)] += 1
    if i < 2:
        print(n, len(b), "rows", len(rows))
        for r in rows[-3:]:
            print("   ", r[:150])
        tail = rows[-1].split("\t", 1)[-1]
        try:
            print("    ROW-LAST", base64.b32decode(gzip.decompress(base64.b64decode(tail))))
        except Exception as ex:
            print("    ROW-LAST fail", repr(ex))
print("row counts", c)
