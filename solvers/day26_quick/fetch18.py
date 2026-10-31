"""Start (or reconnect) an attempt and save start.json + artifact(s) + the question contract. Nothing is executed.
usage: fetch18.py <challenge> <outdir> [start|retry|practice|status] [--deliveries N]"""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gmx import GMX

ch, out = sys.argv[1], sys.argv[2]
op = sys.argv[3] if len(sys.argv) > 3 and not sys.argv[3].startswith("--") else "start"
nd = int(sys.argv[sys.argv.index("--deliveries") + 1]) if "--deliveries" in sys.argv else 0
os.makedirs(out, exist_ok=True)
g = GMX()
st = g.status(ch) if op == "status" else g.post({"op": op, "challenge": ch})
json.dump(st, open(os.path.join(out, "start.json"), "w"), indent=1)
print("mode", st.get("mode"), "deadline", st.get("deadline"), "uar", st.get("unique_attempts_remaining"),
      "nq", len(st.get("questions") or []), "nids", len(st.get("answer_ids") or []), "err", st.get("error"))
if not st.get("answer_ids"):
    print(json.dumps({k: v for k, v in st.items() if k != "guidance"})[:4000]); sys.exit(1)
b = g.artifact(ch)
open(os.path.join(out, "artifact.bin"), "wb").write(b)
print("artifact", len(b), b[:8])
for d in range(1, nd + 1):
    try:
        bb = g.artifact(ch, d)
        if bb[:1] == b"{" and len(bb) < 300:
            print("delivery", d, bb); break
        open(os.path.join(out, "artifact_%d.bin" % d), "wb").write(bb)
        print("delivery", d, len(bb), bb[:8])
    except Exception as e:
        print("delivery", d, "ERR", e); break
qs = st.get("questions") or []
seen = set()
for q in qs:
    key = (q.get("id"), q.get("question"), json.dumps(q.get("answer_format")))
    if key in seen:
        continue
    seen.add(key)
    print("---", q.get("set"), q.get("id"), "|", q.get("artifact"))
    print("   Q:", (q.get("question") or "")[:1500])
    for k in ("answer_format", "normalization", "kind", "accepted_values", "format"):
        if q.get(k) is not None:
            print("   %s:" % k, json.dumps(q.get(k))[:600])
print("ids:", st.get("answer_ids")[:60])
