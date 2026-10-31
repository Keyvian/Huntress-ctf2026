"""Dump op=status for challenges into ~/d30q/status_<id>.json and print a summary."""
import sys, json, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gmx import GMX

g = GMX()
os.makedirs("~/d30q", exist_ok=True)
for ch in sys.argv[1:]:
    r = g.status(ch)
    json.dump(r, open("~/d30q/status_" + ch.replace("/", "_") + ".json", "w"), indent=1)
    print(ch, json.dumps(r)[:4000])
    print()
