"""usage: confirm.py <base challenge id> -> re-read the verdict of all three modes"""
import sys, time
sys.path.insert(0, "~/ctf")
from gm import GM

base = sys.argv[1]
g = GM()
for ch in (base, base + "/time_trial", base + "/mastery"):
    r = None
    for i in range(6):
        try:
            r = g.status(ch)
        except Exception as e:
            r = {"error": repr(e)}
        if isinstance(r, dict) and not r.get("error"):
            break
        time.sleep(1.5 + 1.5 * i)
    print("%-62s result=%-10s flag=%s solved=%s nq=%s" % (
        ch, r.get("result"), r.get("flag"), r.get("solved"), len(r.get("questions") or [])))
