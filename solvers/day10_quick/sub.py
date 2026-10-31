"""sub.py <challenge> '<json answers>'  -> submit and print compact result"""
import sys, json
sys.path.insert(0, "~/ctf")
from gm import GM
r = GM().submit(sys.argv[1], json.loads(sys.argv[2]))
print({k: r.get(k) for k in ("result", "remaining", "flag", "error", "status")})
