"""usage: psplans.py <dir> -> per-set decoded JSON of every composite .ps1 plus the resolved triple"""
import sys, os, json
sys.path.insert(0, "~/ctf")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import s9, s23
from sdec import decode_specimen

st, sets = s9.load(sys.argv[1])
for k in sorted(sets):
    for name, b in sorted(sets[k].items()):
        if not name.endswith(".ps1"):
            continue
        dec = decode_specimen(name, b.decode("utf-8-sig", "replace"))
        pl = dec.get("plan") or {}
        if not pl:
            continue
        trip = s23.ps_composite(pl)
        bad = [x for x in ("url", "secondary", "tertiary") if not trip.get(x)]
        print("set%-2d %-14s %sJSON=%s" % (k, name, "MISS:%s " % ",".join(bad) if bad else "", json.dumps(pl)))
