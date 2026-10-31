import sys, json, time
sys.path.insert(0, "~/ctf")
from gm import GM

ch = sys.argv[1]
out = sys.argv[2]
g = GM()
d = 1.5
for i in range(8):
    r = g.status(ch)
    if not (isinstance(r, dict) and r.get("error") == "rate_limited"):
        break
    time.sleep(d); d = min(d * 1.6, 10)
json.dump(r, open(out, "w"), indent=1)
print({k: (v if k != "questions" else len(v)) for k, v in r.items()} if isinstance(r, dict) else r)
