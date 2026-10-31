"""Debug helper: print every `NN\\t` row of a warmup blob with the candidate decodes warm26's line_decode_l offers for it
(label, text), best first, after learning the per-position codec ranks from a whole blob directory.
usage: warm_rows26.py <blob dir> <blob file> [<blob file> ...]"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import warm26  # noqa: F401  (installs the codecs)
import warm24

d = sys.argv[1]
blobs = [open(os.path.join(d, fn), "rb").read() for fn in sorted(os.listdir(d)) if not fn.endswith(".json")]
warm24.learn_positions(blobs)
for fn in sys.argv[2:]:
    raw = open(fn, "rb").read()
    s = raw.decode("utf-8", "replace")
    print("=====", fn)
    for i, f in warm24._rows(s):
        lc = warm24.line_decode_l(f)
        rank = warm24.POS_RANK.get(i)
        print("%02d %-45r rank=%s" % (i, f[:45], (rank or [])[:3]))
        for lab, x in lc[:6]:
            print("      %-8s %r" % (lab, x))
    slug, msg = warm24.solve_blob(raw)
    print("  ->", slug, "|", msg)
