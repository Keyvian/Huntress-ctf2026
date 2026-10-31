"""submit a small JSON answer dict to a challenge. usage: sub.py <challenge> '<json>'"""
import sys, os, json, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gmx import GMX

ch, ans = sys.argv[1], json.loads(sys.argv[2])
g = GMX()
t0 = time.time()
r = g.submit(ch, ans)
print("SUBMIT", json.dumps(r)[:1500], "%.2fs" % (time.time() - t0))
