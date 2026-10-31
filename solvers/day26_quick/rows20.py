"""debug: per-row candidates of a mixed-codec NN\t blob (warm19 line_decode_l) with timing; optional POS_RANK learning over a dir."""
import sys, os, time, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.argv = [sys.argv[0], "local", "/nonexistent"] if len(sys.argv) < 2 else sys.argv
import importlib.util
spec = importlib.util.spec_from_file_location("w19", os.path.join(os.path.dirname(os.path.abspath(__file__)), "warm19.py"))
src = open(spec.origin, encoding="utf-8").read().replace("\nmain()\n", "\n")
w = type(sys)("w19"); w.__file__ = spec.origin
exec(compile(src, spec.origin, "exec"), w.__dict__)

d = sys.argv[1]
fns = sorted(f for f in os.listdir(d) if f.startswith("blob"))
blobs = [open(os.path.join(d, f), "rb").read() for f in fns]
t0 = time.time()
if len(blobs) > 1:
    w.learn_positions(blobs)
    print("learn %.2fs" % (time.time() - t0))
    for k, v in sorted(w.POS_RANK.items()):
        print("  pos", k, v[:4])
target = sys.argv[2] if len(sys.argv) > 2 else fns[0]
s = open(os.path.join(d, target), "rb").read().decode()
for i, f in w._rows(s):
    t1 = time.time()
    lc = w.line_decode_l(f)
    rank = w.POS_RANK.get(i)
    if rank:
        lc.sort(key=lambda t: (rank.index(t[0]) if t[0] in rank else 99, -w.eng_score(t[1])))
    else:
        lc.sort(key=lambda t: -w.eng_score(t[1]))
    print("%2d %-45r %.3fs -> %s" % (i, f[:45], time.time() - t1, [(l, x[:14]) for l, x in lc[:5]]))
t1 = time.time()
r = w.solve_mixed(s)
print("solve_mixed %.2fs ->" % (time.time() - t1), r and r[0], "|", (r and r[1][:120]))
