"""Day-31 peek: full bytes of each dead-end member, and every PowerShell edge line with mismatched quotes + whether it sits on the chain.
usage: peek31e.py <evidence artifact.bin>"""
import sys, io, os, re
import pyzipper
import graph31


def zlist(b):
    z = pyzipper.AESZipFile(io.BytesIO(b))
    z.setpassword(b"infected")
    return z, [i for i in z.infolist() if not i.filename.endswith("/")]


top = open(sys.argv[1], "rb").read()
z, ms = zlist(top)
nmis_chain = nmis_cycle = 0
for i in ms:
    if not i.filename.endswith(".zip"):
        continue
    e, em = zlist(z.read(i.filename))
    for j in em:
        if os.path.basename(j.filename) != "case-001.zip":
            continue
        cb = e.read(j.filename)
        nodes, g, kinds, term, stray = graph31.analyse(cb)
        roots, indeg, res = graph31.chains(g, term)
        path, why = res[0]
        endn = path[-1]
        b = nodes[endn]
        print("==", i.filename, why, endn, kinds[endn])
        if kinds[endn] == "sqlite":
            print("   sqlite", graph31.sqlite_rows(b))
        elif kinds[endn] == "zip":
            zz, mm = zlist(b)
            print("   zip", [(k.filename, zz.read(k.filename)) for k in mm])
        elif why != "terminal":
            print("   raw", b)
        for n, d in nodes.items():
            if kinds[n] != "ps1":
                continue
            for ln in d.decode("utf-8", "replace").splitlines():
                if ln.startswith("#") or ln.startswith("$"):
                    continue
                m = re.search(r"(['\"]).*?(['\"])\s*$", ln)
                mis = m and m.group(1) != m.group(2)
                if mis:
                    on = n in path
                    nmis_chain += on
                    nmis_cycle += not on
                    print("   MISQUOTE", "CHAIN" if on else "cycle", n, repr(ln))
print("mismatched on chain", nmis_chain, "off chain", nmis_cycle)
