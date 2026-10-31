"""Submit the SHA1-Hulud flag through the Game Master and print the verdict plus a status re-read."""
import json, sys, time
sys.path.insert(0, "~/ctf")
from gm import GM

CH = "binary-reverse-engineering-day-30-sha1-hulud"
g = GM()
d = 1.5
for i in range(8):
    r = g.submit(CH, {"flag": sys.argv[1]})
    if not (isinstance(r, dict) and r.get("error") == "rate_limited"):
        break
    time.sleep(d); d = min(d * 1.6, 10)
print("SUBMIT", json.dumps({k: v for k, v in r.items() if k != "guidance"}, ensure_ascii=False)[:700])
s = g.status(CH)
print("STATUS", json.dumps({k: v for k, v in s.items() if k in ("result", "flag", "solved", "status", "error", "attempt_id", "mode")}, ensure_ascii=False)[:400])
