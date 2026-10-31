"""Start (or resume) a challenge, save the start JSON and the default artifact (+ optional deliveries).
usage: d9start.py <challenge> <outdir> [deliveries e.g. 0,1,2] [--practice]"""
import sys, os, json, io, zipfile
sys.path.insert(0, "~/ctf")
from gm import GM
g = GM()
ch, out = sys.argv[1], sys.argv[2]
os.makedirs(out, exist_ok=True)
st = g.practice(ch) if "--practice" in sys.argv else g.start(ch)
json.dump(st, open(os.path.join(out, "start.json"), "w"), indent=1, ensure_ascii=False)
s = {k: v for k, v in st.items() if k not in ("questions", "guidance", "answer_ids")}
print("START", json.dumps(s, ensure_ascii=False)[:1500])
aids = st.get("answer_ids") or []
print("N_AIDS", len(aids), aids[:40])
for q in (st.get("questions") or [])[:30]:
    print("Q", json.dumps(q, ensure_ascii=False)[:600])
print("NQ", len(st.get("questions") or []))
dels = [None]
if len(sys.argv) > 3 and not sys.argv[3].startswith("--"):
    dels += [int(x) for x in sys.argv[3].split(",")]
for d in dels:
    b = g.artifact(ch, d)
    fn = os.path.join(out, "artifact%s.bin" % ("" if d is None else "_d%d" % d))
    open(fn, "wb").write(b)
    print("ART", d, len(b), b[:80])
