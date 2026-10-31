import sys
sys.path.insert(0, "~/ctf")
from gm import GM
N = sys.argv[1] if len(sys.argv) > 1 else ""
j = GM().get("?op=list&day=%s" % N).json()
items = j if isinstance(j, list) else (j.get("challenges") or j.get("items") or [])
bases = sorted({(c.get("id") or "").split("/")[0] for c in items if isinstance(c, dict)})
GROUP = {"warmups": "quick", "metadata-forensics": "quick", "mobile-android": "quick",
         "script-analysis": "script", "binary-reverse-engineering": "binary"}
# web has its own watchdog (webwatch.py); welcome ids are day-1 orientation
SKIP = ("web-exploitation", "welcome-robots", "read-the-rules")
for b in bases:
    if not b or b.startswith(SKIP):
        continue
    for pfx, grp in GROUP.items():
        if b.startswith(pfx):
            print("%s\t%s" % (grp, b))
            break
    else:
        # 2026-10-29: unknown lane (e.g. Day-30 standard RE challenge) -> catch-all group
        print("extra\t%s" % b)
