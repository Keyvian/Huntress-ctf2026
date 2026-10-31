"""Day-31 peek: for each mastery set, show the case's chains, the end member's raw bytes and any type the extractor did not recognise.
usage: peek31d.py <evidence artifact.bin>"""
import sys, io, os, collections
import pyzipper
import graph31


def zlist(b):
    z = pyzipper.AESZipFile(io.BytesIO(b))
    z.setpassword(b"infected")
    return z, [i for i in z.infolist() if not i.filename.endswith("/")]


top = open(sys.argv[1], "rb").read()
z, ms = zlist(top)
kinds_all = collections.Counter()
for i in ms:
    if not i.filename.endswith(".zip"):
        continue
    e, em = zlist(z.read(i.filename))
    for j in em:
        if os.path.basename(j.filename) != "case-001.zip":
            continue
        cb = e.read(j.filename)
        nodes, g, kinds, term, stray = graph31.analyse(cb)
        kinds_all.update(kinds.values())
        roots, indeg, res = graph31.chains(g, term)
        print("==", i.filename, "nodes", len(nodes), "kinds", dict(collections.Counter(kinds.values())), "roots", len(roots), "stray", stray)
        for p, w in res:
            print("   ", len(p), w, p)
            print("    END", repr(nodes[p[-1]][:160]))
        covered = {n for p, _ in res for n in p}
        rest = [n for n in g if n not in covered]
        dang = [n for n in g if not g[n]]
        print("    rest", len(rest), "no-out", dang, "indeg>1", [n for n, c in indeg.items() if c > 1], "outdeg>1", [n for n in g if len(g[n]) > 1])
print(kinds_all)
