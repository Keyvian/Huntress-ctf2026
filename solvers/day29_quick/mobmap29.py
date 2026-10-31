"""Check the mastery set <-> delivery mapping: package named in each setN question vs the dex package inside
artifact.bin (set 1) / artifact<k>.bin (set k+1). usage: mobmap29.py <saved dir>"""
import json, re, zipfile, io, os, sys

dd = sys.argv[1]
st = json.load(open(os.path.join(dd, "start.json")))
qp = {q["id"]: re.search(r"package (\S+?):", q["question"]).group(1) for q in st["questions"]}


def pkgs(b):
    out = set()
    z = zipfile.ZipFile(io.BytesIO(b))
    for n in z.namelist():
        if n.endswith(".dex"):
            out |= {x.decode().replace("/", ".") for x in re.findall(rb"Lcom/huntress/mobile/(d\d+/v[0-9a-f]+)/", z.read(n))}
        elif n.endswith((".apk", ".apks")):
            out |= pkgs(z.read(n))
    return out


n = len(qp)
ok = 0
for i in range(n):
    f = "artifact.bin" if i == 0 else "artifact%d.bin" % i
    p = pkgs(open(os.path.join(dd, f), "rb").read())
    want = qp["set%d.answer" % (i + 1)]
    m = any(want.endswith(x) for x in p)
    ok += m
    print(i + 1, f, want, sorted(p), m)
print("match %d/%d" % (ok, n))
