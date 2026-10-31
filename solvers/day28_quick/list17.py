"""print the Day-N list entries for the quick lanes (descriptions / pool sizes). usage: list17.py <day>"""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gmx import GMX

day = sys.argv[1] if len(sys.argv) > 1 else "17"
g = GMX()
r = g.get("?op=list&day=%s" % day)
try:
    r = r.json()
except Exception:
    pass
items = r if isinstance(r, list) else (r.get("challenges") or r.get("items") or r)
for c in items:
    if isinstance(c, dict) and any(k in str(c.get("id", "")) for k in ("warmups", "metadata", "mobile")):
        print(json.dumps(c, ensure_ascii=False)[:2500])
        print()
