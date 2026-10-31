"""Re-read the Day-30 quick-lane verdicts through op=status (result + flag per mode)."""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gmx import GMX

g = GMX()
ok = 0
ids = []
for base in ("warmups-day-30", "metadata-forensics-day-30-seeing-double", "mobile-android-day-30-layered-protections"):
    ids += [base, base + "/time_trial", base + "/mastery"]
for ch in ids:
    st = g.status(ch)
    r = st.get("result")
    fl = st.get("flag")
    print("%-60s result=%-9s flag=%s nq=%s deadline=%s" % (ch, r, fl, len(st.get("questions") or []), st.get("deadline")))
    ok += 1 if r == "CORRECT" or fl else 0
    time.sleep(1.2)
print("CONFIRMED %d/%d" % (ok, len(ids)))
