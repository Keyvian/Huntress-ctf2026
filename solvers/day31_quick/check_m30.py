"""Cross-check the mastery relation answers against each set's own evidence-NN.zip, and show the singleton near-duplicates.
usage: check_m30.py <saved mastery dir>"""
import sys, os, io, re, json, zipfile, hashlib, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import m30, m15, rel30

d = sys.argv[1]
st = json.load(open(os.path.join(d, "start.json")))
raw = open(os.path.join(d, "artifact.bin"), "rb").read()
files = m15.unzip_all(raw)
ans, unk = m30.solve(st, files)
print("unknown", len(unk))
outer = zipfile.ZipFile(io.BytesIO(raw))
print("outer", outer.namelist()[:16])
bad = 0
for q in st["questions"]:
    if "relation-identical" not in q["id"]:
        continue
    n = int(re.match(r"set(\d+)\.", q["id"]).group(1))
    b = zipfile.ZipFile(io.BytesIO(outer.read("evidence-%02d.zip" % n))).read("cluster-001.zip")
    mem = rel30.members(b)
    exp = json.dumps(rel30.groups(b), separators=(",", ":"))
    got = ans.get(q["id"])
    gs = json.loads(exp)
    flat = {x for g in gs for x in g}
    sing = [p.rsplit("/", 1)[-1] for p, _ in mem if p.rsplit("/", 1)[-1] not in flat]
    names = [p for p, _ in mem]
    print("set%-2d %s members %d dupnames %d manifest %s groups %s singletons %d %s" % (
        n, "OK " if exp == got else "BAD", len(mem), len(names) - len(set(names)), rel30.manifest(b) is not None,
        [len(g) for g in gs], len(sing), sing[:7]))
    bad += exp != got
print("bad", bad)
