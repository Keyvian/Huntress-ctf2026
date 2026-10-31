"""usage: rolediff.py <dir>
For every *-role question, print where the Day-22 classifier (s9) and the Day-23 terminal-intent
classifier disagree, so a validated answer is never silently replaced."""
import sys, os, re, json
sys.path.insert(0, "~/ctf")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import s9, s23
from sdec import decode_specimen

st, sets = s9.load(sys.argv[1])
n = same = 0
for q in st["questions"]:
    if not re.sub(r"^set\d+\.", "", q["id"]).endswith("-role"):
        continue
    fname = (q.get("artifact") or "").split("->")[-1].strip()
    sm = re.match(r"set(\d+)\.", q["id"])
    k = int(sm.group(1)) if sm else 1
    files = sets.get(k) or sets.get(1)
    if fname not in files:
        continue
    t = files[fname].decode("utf-8-sig", "replace")
    dec = decode_specimen(fname, t)
    p = s9.flat_plan(dec)
    old = s9.answer(q["id"], fname, t, dec)
    new = p.get("role") or s23.role_terminal((p.get("steps") or "").split(","))
    n += 1
    if old == new:
        same += 1
    else:
        print("DIFF %-34s plan_role=%-22s s9=%-22s terminal=%-22s steps=%s"
              % (q["id"], p.get("role"), old, s23.role_terminal((p.get("steps") or "").split(",")),
                 p.get("steps")))
print("role questions", n, "agree", same, "differ", n - same)
