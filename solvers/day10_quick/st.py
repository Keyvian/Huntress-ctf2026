import sys, json
sys.path.insert(0, "~/ctf")
from gm import GM
g = GM()
q = sys.argv[1] if len(sys.argv) > 1 else "?op=list&day=10"
j = g.get(q).json()
if isinstance(j, dict) and "challenges" in j:
    out = []
    for c in j["challenges"]:
        c = dict(c); c.pop("guidance", None)
        if any(k in c["id"] for k in ("warmups", "metadata", "mobile")):
            out.append(c)
    j = out
print(json.dumps(j, indent=1)[:int(sys.argv[2]) if len(sys.argv) > 2 else 60000])
