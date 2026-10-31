"""usage: fetch.py <challenge> <outdir> [--deliveries N]  -> start + save start.json + artifact.bin (+artifact_dK.bin)"""
import sys, os, json
sys.path.insert(0, "~/ctf")
from gm import GM
ch, dd = sys.argv[1], sys.argv[2]
os.makedirs(dd, exist_ok=True)
g = GM()
st = g.start(ch)
json.dump(st, open(os.path.join(dd, "start.json"), "w"), indent=1)
print("mode", st.get("mode"), "deadline", st.get("deadline"), "nq", len(st.get("questions") or []),
      "naid", len(st.get("answer_ids") or []), "err", st.get("error"), "keys", list(st)[:30])
b = g.artifact(ch)
open(os.path.join(dd, "artifact.bin"), "wb").write(b)
print("artifact", len(b), b[:4])
nd = int(sys.argv[sys.argv.index("--deliveries") + 1]) if "--deliveries" in sys.argv else 0
for k in range(nd):
    b = g.artifact(ch, k)
    if b[:1] == b"{":
        print("delivery", k, b[:120]); continue
    open(os.path.join(dd, "artifact_d%d.bin" % k), "wb").write(b)
    print("delivery", k, len(b), b[:4])
