"""Re-read the Day-31 quick-lane verdicts through op=status (result + flag per mode)."""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gmx import GMX

g = GMX()
ok = 0
ids = []
for base in ("warmups-day-31", "metadata-forensics-day-31-no-artifact-left-behind", "mobile-android-day-31-mobile-arena-gauntlet"):
    ids += [base, base + "/time_trial", base + "/mastery"]
for ch in ids:
    st = g.status(ch)
    r = st.get("result")
    fl = st.get("flag")
    print("%-60s result=%-9s flag=%s nq=%s deadline=%s" % (ch, r, fl, len(st.get("questions") or []), st.get("deadline")))
    ok += 1 if r == "CORRECT" or fl else 0
    time.sleep(1.2)
print("CONFIRMED %d/%d" % (ok, len(ids)))
