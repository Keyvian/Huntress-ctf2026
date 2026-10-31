"""start/retry/practice a challenge, save start.json + default artifact (+ optional deliveries) to <outdir>.
usage: fetch.py <challenge> <outdir> [op] [ndeliveries]"""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gmx import GMX

ch, out = sys.argv[1], sys.argv[2]
op = sys.argv[3] if len(sys.argv) > 3 else "start"
nd = int(sys.argv[4]) if len(sys.argv) > 4 else 0
g = GMX()
os.makedirs(out, exist_ok=True)
st = g.post({"op": op, "challenge": ch})
json.dump(st, open(os.path.join(out, "start.json"), "w"), indent=1)
print("mode", st.get("mode"), "deadline", st.get("deadline"), "uar", st.get("unique_attempts_remaining"),
      "nq", len(st.get("questions") or []), "nids", len(st.get("answer_ids") or []), "err", st.get("error"))
b = g.artifact(ch)
open(os.path.join(out, "artifact.bin"), "wb").write(b)
print("artifact", len(b), b[:8])
for d in range(1, nd + 1):
    b = g.artifact(ch, d)
    open(os.path.join(out, "artifact_d%d.bin" % d), "wb").write(b)
    print("delivery", d, len(b), b[:40])
