import sys
sys.path.insert(0, "~/ctf")
from gm import GM
try:
    j = GM().get("?op=list&all=true").json()
    items = j if isinstance(j, list) else (j.get("challenges") or j.get("items") or [])
    days = {(c.get("id") or "").split("-day-")[-1][:2] for c in items if isinstance(c, dict)}
    # 2026-10-29: also use the GM release-day field, so a challenge whose id has no
    # "-day-NN" (e.g. the Day-30 standard RE challenge) still moves the day number.
    days |= {"%02d" % c["day"] for c in items if isinstance(c, dict) and isinstance(c.get("day"), int)}
    days = sorted(d for d in days if d.isdigit())
    print("COUNT=%d DAYS=%s" % (len(items), ",".join(days)))
except Exception as e:
    print("COUNT=ERR %s" % e)
