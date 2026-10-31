"""Submit single answers one at a time (untimed banking probe).
usage: probe.py <challenge> <json-file-or-inline-json: [[id, value], ...]> [--stop-on-accept]"""
import sys, json, time, os
sys.path.insert(0, "~/ctf")
from gm import GM
g = GM()
ch = sys.argv[1]
arg = sys.argv[2]
pairs = json.load(open(arg)) if os.path.exists(arg) else json.loads(arg)
done = set()
for k, v in pairs:
    if "--stop-on-accept" in sys.argv and k in done:
        continue
    for attempt in range(6):
        r = g.submit(ch, {k: str(v)})
        res = r.get("result") if isinstance(r, dict) else None
        if res or r.get("flag"):
            break
        time.sleep(2 + 2 * attempt)
    print("%-45s %-60s -> %s rem=%s flag=%s err=%s" % (k, str(v)[:60], res, r.get("remaining"), r.get("flag"), r.get("error")))
    if res in ("accepted", "CORRECT", "correct", "already_solved") or r.get("flag"):
        done.add(k)
    time.sleep(1.6)
