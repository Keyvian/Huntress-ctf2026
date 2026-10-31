"""Start (or resume) a challenge with rate-limit backoff, save start.json + default artifact (+ deliveries).
usage: d11start.py <challenge> <outdir> [deliveries e.g. 1,2] [--practice|--retry]"""
import sys, os, json, time
sys.path.insert(0, "~/ctf")
from gm import GM
g = GM()
ch, out = sys.argv[1], sys.argv[2]
os.makedirs(out, exist_ok=True)


def call(f, *a):
    d = 1.0
    for _ in range(12):
        r = f(*a)
        if isinstance(r, dict) and r.get("error") == "rate_limited":
            time.sleep(d); d = min(d * 1.6, 8); continue
        if isinstance(r, (bytes, bytearray)) and r.startswith(b'{"error":"rate_limited"'):
            time.sleep(d); d = min(d * 1.6, 8); continue
        return r
    return r


op = "practice" if "--practice" in sys.argv else ("retry" if "--retry" in sys.argv else "start")
st = call(getattr(g, op), ch)
json.dump(st, open(os.path.join(out, "start.json"), "w"), indent=1, ensure_ascii=False)
s = {k: v for k, v in st.items() if k not in ("questions", "guidance", "answer_ids")}
print("START", json.dumps(s, ensure_ascii=False)[:1500])
aids = st.get("answer_ids") or []
print("N_AIDS", len(aids))
print("NQ", len(st.get("questions") or []))
dels = [None]
if len(sys.argv) > 3 and not sys.argv[3].startswith("--"):
    dels += [int(x) for x in sys.argv[3].split(",")]
for d in dels:
    b = call(g.artifact, ch, d)
    fn = os.path.join(out, "artifact%s.bin" % ("" if d is None else "_d%d" % d))
    open(fn, "wb").write(b)
    print("ART", d, len(b), b[:80])
