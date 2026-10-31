import sys, json
sys.path.insert(0, "~/ctf")
from gm import GM
g = GM()
CH = "script-analysis-day-10-wmi-persistence-reconstruction"
j = g.get("?op=list&day=10").json()
items = j if isinstance(j, list) else (j.get("challenges") or j.get("items") or [])
for it in items:
    if "script" in json.dumps(it):
        print(json.dumps(it, indent=1)[:4000])
for m in (CH, CH + "/time_trial", CH + "/mastery"):
    print("=====", m)
    print(json.dumps(g.status(m), indent=1)[:6000])
