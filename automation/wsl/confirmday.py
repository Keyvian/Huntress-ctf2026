import sys
sys.path.insert(0, "~/ctf")
from gm import GM
N = sys.argv[1]; g = GM()
j = g.get("?op=list&day=%s" % N).json()
items = j if isinstance(j, list) else (j.get("challenges") or j.get("items") or [])
bases = sorted({(c.get("id") or "").split("/")[0] for c in items if isinstance(c, dict)})
solved = 0; tot = 0
for b in bases:
    lane = b.split("-day-")[0]
    for mode in ("", "/time_trial", "/mastery"):
        st = g.status(b + mode); r = st.get("result"); ok = (r == "CORRECT")
        solved += ok; tot += 1
        print(("OK " if ok else "-- "), lane + (mode or "/single"), "->", r)
print("TOTAL %d/%d" % (solved, tot))
