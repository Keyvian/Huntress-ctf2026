"""start (or status/retry/practice) a challenge, save start.json + artifact(s) under a dir, print the contract.
usage: st16.py <challenge> <outdir> [start|retry|practice|status] [--rft] [--deliveries N]"""
import sys, os, json, time, io, zipfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gmx import GMX

ch, out = sys.argv[1], sys.argv[2]
op = sys.argv[3] if len(sys.argv) > 3 and not sys.argv[3].startswith("--") else "start"
os.makedirs(out, exist_ok=True)
g = GMX()
t0 = time.time()
body = {"op": op, "challenge": ch}
if "--rft" in sys.argv:
    body["run_for_time"] = True
st = g.post(body) if op != "status" else g.status(ch)
json.dump(st, open(os.path.join(out, "start.json"), "w"), indent=1)
print("mode", st.get("mode"), "deadline", st.get("deadline"), "uar", st.get("unique_attempts_remaining"),
      "nq", len(st.get("questions") or []), "nids", len(st.get("answer_ids") or []), "err", st.get("error"))
for k in ("attempt_id", "download", "sha256", "status", "solved", "result", "regular", "ranked", "run_for_time"):
    if k in st:
        print(" ", k, "=", st[k])
if st.get("answer_ids"):
    b = g.artifact(ch)
    open(os.path.join(out, "artifact.bin"), "wb").write(b)
    print("artifact", len(b), b[:4])
    nd = int(sys.argv[sys.argv.index("--deliveries") + 1]) if "--deliveries" in sys.argv else 0
    for d in range(1, nd + 1):
        bb = g.artifact(ch, d)
        if bb[:1] == b"{" and len(bb) < 300:
            print("delivery", d, bb); break
        open(os.path.join(out, "artifact%d.bin" % d), "wb").write(bb)
        print("delivery", d, len(bb), bb[:4])
    if b[:2] == b"PK":
        try:
            z = zipfile.ZipFile(io.BytesIO(b))
            for zi in z.infolist()[:60]:
                print("   ", zi.filename, zi.file_size)
        except Exception as e:
            print("zip?", e)
qs = st.get("questions") or []
seen = set()
for q in qs:
    key = (str(q.get("question")), str(q.get("answer_format")))
    tag = "" if key not in seen else " (dup wording)"
    seen.add(key)
    if tag and len(qs) > 40:
        continue
    print(json.dumps({k: q.get(k) for k in ("id", "set", "artifact", "answer_format", "normalization")}), "\n   Q:", q.get("question"))
print("ids", (st.get("answer_ids") or [])[:40])
print("%.1fs" % (time.time() - t0))
