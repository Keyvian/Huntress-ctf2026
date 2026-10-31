"""Fetch artifact deliveries into a cache dir with retry. usage: fetchdel.py <challenge> <outdir> <d1,d2,...>"""
import sys, os, time
sys.path.insert(0, "~/ctf")
from gm import GM
g = GM()
ch, out = sys.argv[1], sys.argv[2]
for d in [int(x) for x in sys.argv[3].split(",")]:
    fn = os.path.join(out, "artifact_d%d.bin" % d)
    if os.path.exists(fn) and open(fn, "rb").read(2) == b"PK":
        print("cached", d); continue
    for a in range(8):
        b = g.artifact(ch, d)
        if b[:2] == b"PK":
            open(fn, "wb").write(b); print("delivery", d, len(b)); break
        print("delivery", d, "retry", a, b[:200]); time.sleep(3 + 3 * a)
    time.sleep(1.5)
