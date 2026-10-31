"""Re-read op=status for every Day-31 binary mode; print the verdict and flag the Game Master has on record."""
import json, sys, time
sys.path.insert(0, "~/ctf")
from gm import GM

g = GM()
B = "binary-reverse-engineering-day-31-reversing-gauntlet"
for ch in (B, B + "/time_trial", B + "/mastery"):
    d = 1.5
    for i in range(8):
        r = g.status(ch)
        if not (isinstance(r, dict) and r.get("error") == "rate_limited"):
            break
        time.sleep(d); d = min(d * 1.6, 10)
    print(ch.replace(B, "") or "single", {k: r.get(k) for k in ("result", "flag", "error", "mode")})
    time.sleep(0.5)
