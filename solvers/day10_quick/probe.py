"""probe.py <challenge> <outdir> [op=start|retry|practice|none] [delivery]
Start (or resume) an attempt, dump the start response, fetch the artifact to outdir."""
import sys, json, os, io, zipfile
sys.path.insert(0, "~/ctf")
from gm import GM
g = GM()
ch, outd = sys.argv[1], sys.argv[2]
op = sys.argv[3] if len(sys.argv) > 3 else "start"
dl = sys.argv[4] if len(sys.argv) > 4 else None
os.makedirs(outd, exist_ok=True)
if op != "none":
    r = g.post({"op": op, "challenge": ch})
    open(os.path.join(outd, "start_%s.json" % op), "w").write(json.dumps(r, indent=1))
    rr = dict(r)
    print(json.dumps(rr, indent=1)[:12000])
b = g.artifact(ch, dl)
fn = os.path.join(outd, "artifact%s.bin" % ("" if dl is None else "_d" + dl))
open(fn, "wb").write(b)
print("artifact bytes", len(b), b[:80])
