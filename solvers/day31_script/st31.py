"""usage: st31.py <challenge> <out.json>  -> op=status with rate-limit backoff, prints a contract summary"""
import sys, json, time, collections
sys.path.insert(0, "~/ctf")
from gm import GM
ch, out = sys.argv[1], sys.argv[2]
g = GM()
r = {}
for i in range(12):
    r = g.status(ch)
    if isinstance(r, dict) and r.get("error") == "rate_limited":
        time.sleep(2 + i * 2); continue
    break
json.dump(r, open(out, "w"), indent=1)
print({k: (v if not isinstance(v, (list, dict)) else (type(v).__name__, len(v))) for k, v in r.items()})
print("NAME", r.get("name") or r.get("title"))
print("PROMPT", r.get("prompt") or r.get("description"))
qs = r.get("questions") or []
print("nq", len(qs))
print(collections.Counter((q.get("artifact") or "").split("->")[-1].strip().rsplit(".", 1)[-1] for q in qs).most_common(60))
