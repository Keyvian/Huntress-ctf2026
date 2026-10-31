"""Read the Day-31 binary contract (list entry + op=status per mode) into ~/d31."""
import sys, json, os
sys.path.insert(0, "~/ctf")
from gm import GM
g = GM()
os.makedirs("~/d31", exist_ok=True)
os.chdir("~/d31")
j = g.get("?op=list&day=31").json()
items = j if isinstance(j, list) else (j.get("challenges") or j.get("items") or j)
for it in items:
    if isinstance(it, dict) and "binary" in str(it.get("id", "")):
        print(json.dumps(it)[:1500])
ch = "binary-reverse-engineering-day-31-reversing-gauntlet"
for m in ["", "/time_trial", "/mastery"]:
    s = g.status(ch + m)
    json.dump(s, open("status0%s.json" % m.replace("/", "_"), "w"), indent=1)
    t = json.dumps(s)
    print(repr(m), len(t), t[:2500])
    print()
