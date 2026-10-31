"""List the Batch reconstruction regions across cached script-lane dirs (static text only, never executes).
usage: batshapes.py <dir> [<dir> ...]"""
import sys, os, re, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from s9 import load, batch_styles

for dd in sys.argv[1:]:
    try:
        st, sets = load(dd)
    except Exception as e:
        print("##", dd, "LOAD-ERR", e); continue
    ans = {}
    if os.path.exists(os.path.join(dd, "answers.json")):
        ans = json.load(open(os.path.join(dd, "answers.json")))
    for k, files in sorted(sets.items()):
        for fn, b in sorted(files.items()):
            if not fn.endswith((".cmd", ".bat")):
                continue
            t = b.decode("utf-8-sig", "replace")
            region = t.split(":HUNTRESS_SEPARATOR_DONE", 1)[-1]
            region = region.split(":HUNTRESS_UNUSED", 1)[0]
            lines = [l for l in region.splitlines() if l.strip() and not l.startswith("set \"neutral")]
            qs = [q["id"] for q in st["questions"] if (q.get("artifact") or "").endswith(" " + fn)
                  and (q["id"].startswith("set%d." % k) or not q["id"].startswith("set"))]
            ex = next((ans.get(q) for q in qs if q.endswith("-expansion")), None)
            co = next((ans.get(q) for q in qs if q.endswith("-control")), None)
            print("## %s set%d %s  ans=%s/%s  cur=%s" % (dd.split("~/")[-1], k, fn, ex, co, batch_styles(t)))
            for l in lines:
                print("    " + l[:200])
