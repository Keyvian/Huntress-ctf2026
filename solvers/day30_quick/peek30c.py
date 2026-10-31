"""Summarise the cluster zips of a saved Seeing Double attempt: families, duplicate structure, manifest claims, nested members.
usage: peek30c.py <dir> (walks artifact*.bin; every member named cluster-*.zip at any depth)"""
import sys, os, io, json, zipfile, hashlib, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rel30

d = sys.argv[1]
verbose = len(sys.argv) > 2


def clusters(zb, pre=""):
    z = zipfile.ZipFile(io.BytesIO(zb))
    for i in z.infolist():
        if i.filename.endswith("/"):
            continue
        b = z.read(i.filename)
        if i.filename.rsplit("/", 1)[-1].startswith("cluster-"):
            yield pre + i.filename, b
        elif b[:4] == b"PK\x03\x04" and i.filename.endswith(".zip") and i.filename.startswith("evidence-"):
            yield from clusters(b, pre + i.filename + "/")


for f in sorted(os.listdir(d)):
    if not f.startswith("artifact"):
        continue
    for name, b in clusters(open(os.path.join(d, f), "rb").read()):
        z = zipfile.ZipFile(io.BytesIO(b))
        m = rel30.manifest(b)
        arts = m["artifacts"]
        print("==", name, "size", len(b), "entries", len(z.infolist()), "manifest keys", [k for k in m if k != "artifacts"], "arts", len(arts))
        keys = collections.Counter(tuple(sorted(a)) for a in arts)
        print("   art keys", list(keys.items())[:3])
        print("   producers", collections.Counter(a.get("producer_id") for a in arts), "families", collections.Counter(a.get("family") for a in arts))
        print("   order", [a["id"] for a in arts][:8], "... zip order", [i.filename for i in z.infolist()][:4])
        print("   mismatches", rel30.check_manifest(b)[:8])
        by = collections.defaultdict(list)
        for p, x in rel30.members(b):
            by[hashlib.sha256(x).hexdigest()].append(p.rsplit("/", 1)[-1])
        print("   sha groups", sorted((len(v), v[0], v[-1]) for v in by.values())[:12], "n", len(by))
        print("   answer", json.dumps(rel30.groups(b), separators=(",", ":"))[:420])
        if verbose:
            for p, x in rel30.members(b):
                if x[:2] == b"PK":
                    zz = zipfile.ZipFile(io.BytesIO(x))
                    print("     ZIP", p, [(i.filename, i.file_size, "%08x" % i.CRC) for i in zz.infolist()], zz.testzip())
                elif p.endswith("01.txt") or p.endswith("01.json") or p.endswith("01.ps1"):
                    print("     ", p, x[:120])
