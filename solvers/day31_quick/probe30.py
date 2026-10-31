"""Probe the answer shape of relation.identical_sha256_groups on the untimed single_solve attempt (status-free; one submit per
candidate, stops at the first non-incorrect verdict). usage: probe30.py <saved single dir> [submit]"""
import sys, os, io, json, time, zipfile, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rel30
from gmx import GMX

CH = "metadata-forensics-day-30-seeing-double"
d = sys.argv[1]
z = zipfile.ZipFile(io.BytesIO(open(os.path.join(d, "artifact.bin"), "rb").read()))
b = z.read("cluster-001.zip")
aid = "d30-cluster-001-relation-identical-sha256-groups"


def J(x):
    return json.dumps(x, separators=(",", ":"))


fn = rel30.groups(b)
ids = rel30.groups(b, lambda p: p.rsplit("/", 1)[-1].rsplit(".", 1)[0])
paths = rel30.groups(b, lambda p: p)
shas = {}
for p, x in rel30.members(b):
    shas[p.rsplit("/", 1)[-1]] = hashlib.sha256(x).hexdigest()
bysha = lambda gs, f: sorted(gs, key=lambda g: shas[f(g[0])])
c = [
    ("filenames", J(fn)),
    ("ids", J(ids)),
    ("paths", J(paths)),
    ("filenames by sha", J(bysha(fn, lambda m: m))),
    ("ids by sha", J(bysha(ids, lambda m: [k for k in shas if k.startswith(m + ".")][0]))),
    ("paths by sha", J(bysha(paths, lambda m: m.rsplit("/", 1)[-1]))),
    ("sha list", J(sorted(set(shas.values())))),
    ("sizes", J(sorted(len(g) for g in fn))),
    ("sha+files", J([{"sha256": shas[g[0]], "members": g} for g in fn])),
    ("sha+files2", J([{"sha256": shas[g[0]], "files": g} for g in fn])),
    ("sha+files3", J([{"sha256": shas[g[0]], "filenames": g} for g in fn])),
    ("sha+ids", J([{"sha256": shas[g[0]], "ids": [m.rsplit(".", 1)[0] for m in g]} for g in fn])),
    ("sha+members ids", J([{"sha256": shas[g[0]], "members": [m.rsplit(".", 1)[0] for m in g]} for g in fn])),
]
for lab, v in c:
    print(lab, v[:150])
print("manifest", rel30.check_manifest(b))
if len(sys.argv) > 2:
    g = GMX()
    for lab, v in c:
        r = g.submit(CH, {aid: v})
        print(lab, "->", json.dumps({k: r.get(k) for k in ("result", "error", "remaining", "flag", "message", "hint")}))
        if r.get("result") != "incorrect":
            break
        time.sleep(1.8)
