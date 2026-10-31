"""usage: plandump.py <extracted dir> [name-substring]
Decode every specimen and print its plan keys/values, so new contract fields can be verified."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sdec import decode_specimen

d = sys.argv[1]
pat = sys.argv[2] if len(sys.argv) > 2 else ""
keys = {}
for f in sorted(os.listdir(d)):
    p = os.path.join(d, f)
    if not os.path.isfile(p) or (pat and pat not in f):
        continue
    t = open(p, encoding="utf-8-sig", errors="replace").read()
    dec = decode_specimen(f, t)
    pl = dec.get("plan") or {}
    for k in pl:
        keys[k] = keys.get(k, 0) + 1
    print("== %-22s kind=%-9s rep=%-22s xf=%-18s" % (f, dec.get("kind"), (dec.get("rep") or "")[:22], (dec.get("xf") or "")[:18]))
    if not pl:
        print("   NO PLAN  raw=", (dec.get("raw") or "")[:120])
    else:
        print("   " + " | ".join("%s=%s" % (k, str(v)[:60]) for k, v in pl.items()))
print()
print("PLAN KEY FREQUENCY:", dict(sorted(keys.items(), key=lambda kv: -kv[1])))
