import sys, json
sys.path.insert(0, "~/ctf")
from gm import GM, BASE
g = GM()
r = g.s.get(BASE + "?op=list&all=true", timeout=150)
j = r.json()
chs = j if isinstance(j, list) else (j.get("challenges") or j.get("items") or [])
print("total entries:", len(chs))

def lane_of(cid):
    # strip mode suffix
    base = cid.split("/")[0]
    # lane prefix is everything before -day-
    if "-day-" in base:
        return base.split("-day-")[0]
    return base.rsplit("-", 1)[0] if "-" in base else base

from collections import defaultdict
byl = defaultdict(lambda: {"solved":0,"unsolved":0,"unids":[]})
for c in chs:
    cid = c.get("id","")
    if not cid: continue
    lane = lane_of(cid)
    if c.get("solved"):
        byl[lane]["solved"] += 1
    else:
        byl[lane]["unsolved"] += 1
        byl[lane]["unids"].append(cid)

print("\n=== PER LANE ===")
for lane in sorted(byl):
    d = byl[lane]
    print("%-32s solved=%-4d unsolved=%-4d" % (lane, d["solved"], d["unsolved"]))

print("\n=== UNSOLVED IDS ===")
for lane in sorted(byl):
    for cid in byl[lane]["unids"]:
        print(cid)
