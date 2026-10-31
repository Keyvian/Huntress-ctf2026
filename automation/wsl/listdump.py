import sys, re
sys.path.insert(0, "~/ctf")
from gm import challenges
items = challenges()
print("total:", len(items))
days = {}
for c in items:
    if not isinstance(c, dict):
        continue
    m = re.search(r"day-(\d+)", c.get("id") or "")
    if m:
        days[m.group(1)] = days.get(m.group(1), 0) + 1
print("day -> count:", dict(sorted(days.items())))
nine = sorted({(c.get("id") or "").split("/")[0] for c in items
               if isinstance(c, dict) and re.search(r"day-0?9", c.get("id") or "")})
print("day9 base ids:", nine)
allids = sorted({(c.get("id") or "").split("/")[0] for c in items if isinstance(c, dict)})
print("highest base ids:", allids[-6:])
