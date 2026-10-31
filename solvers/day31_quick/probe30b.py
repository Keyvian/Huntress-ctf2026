"""Bank only relation.identical_sha256_groups on a timed attempt, trying the order conventions in turn (subset submits bank a correct
answer and report `remaining`; a wrong one banks nothing). usage: probe30b.py <challenge> <saved dir>"""
import sys, os, io, json, time, zipfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rel30
from gmx import GMX

ch, d = sys.argv[1], sys.argv[2]
z = zipfile.ZipFile(io.BytesIO(open(os.path.join(d, "artifact.bin"), "rb").read()))
b = z.read("cluster-001.zip")
aid = "d30-cluster-001-relation-identical-sha256-groups"


def J(x):
    return json.dumps(x, separators=(",", ":"))


srt = rel30.groups(b)
c = [
    ("sorted, groups>=2", J(srt)),
    ("archive order, groups>=2", J(rel30.groups(b, sort=False))),
    ("sorted members, first-seen groups", J([sorted(g) for g in rel30.groups(b, sort=False)])),
    ("sorted, by size desc", J(sorted(srt, key=lambda g: (-len(g), g)))),
    ("sorted, with singletons", J(rel30.groups(b, singletons=True))),
]
g = GMX()
for lab, v in c:
    print(lab, v[:230])
    r = g.submit(ch, {aid: v})
    print("  ->", json.dumps({k: r.get(k) for k in ("result", "error", "remaining", "flag")}))
    if r.get("result") != "incorrect":
        break
    time.sleep(1.8)
