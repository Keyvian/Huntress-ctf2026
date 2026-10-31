"""usage: fetch.py <challenge> <outdir> [--deliveries N] [--retry|--practice]
start (with rate-limit backoff) + save start.json + artifact.bin (+artifact_dK.bin)"""
import sys, os, json, time
sys.path.insert(0, "~/ctf")
from gm import GM
ch, dd = sys.argv[1], sys.argv[2]
os.makedirs(dd, exist_ok=True)
g = GM()


def call(fn, *a):
    for i in range(12):
        r = fn(*a)
        if isinstance(r, dict) and r.get("error") == "rate_limited":
            time.sleep(2 + 2 * i); continue
        if isinstance(r, bytes) and r[:30].find(b"rate_limited") >= 0:
            time.sleep(2 + 2 * i); continue
        return r
    return r


op = g.retry if "--retry" in sys.argv else g.practice if "--practice" in sys.argv else g.start
st = call(op, ch)
json.dump(st, open(os.path.join(dd, "start.json"), "w"), indent=1)
print("mode", st.get("mode"), "deadline", st.get("deadline"), "nq", len(st.get("questions") or []),
      "naid", len(st.get("answer_ids") or []), "err", st.get("error"), "keys", list(st)[:30])
b = call(g.artifact, ch)
open(os.path.join(dd, "artifact.bin"), "wb").write(b)
print("artifact", len(b), b[:4])
nd = int(sys.argv[sys.argv.index("--deliveries") + 1]) if "--deliveries" in sys.argv else 0
for k in range(nd):
    b = call(g.artifact, ch, k)
    if b[:1] == b"{":
        print("delivery", k, b[:120]); continue
    open(os.path.join(dd, "artifact_d%d.bin" % k), "wb").write(b)
    print("delivery", k, len(b), b[:4])
