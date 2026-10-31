"""usage: missing.py <dir> [outfile]
Which questions the current solver cannot answer, grouped by normalized id shape + wording."""
import sys, os, json, re, collections
sys.path.insert(0, "~/ctf")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from s9 import load, compute

dd = sys.argv[1]
st, sets = load(dd)
ans, diag = compute(st, sets)
qs = {q["id"]: q for q in st["questions"]}
aids = st.get("answer_ids") or list(qs)
miss = [a for a in aids if a not in ans]
out = open(sys.argv[2], "w", encoding="utf-8") if len(sys.argv) > 2 else sys.stdout


def p(*a):
    print(*a, file=out)


p("computed %d / %d   missing %d" % (len(ans), len(aids), len(miss)))


def shape(qid):
    i = re.sub(r"^set\d+\.", "", qid)
    return re.sub(r"-(?:[0-9a-f]{6}|[0-9a-f]{8})-", "-*-", i)


g = collections.OrderedDict()
for a in miss:
    q = qs[a]
    fn = (q.get("artifact") or "").split("->")[-1].strip()
    stem = re.sub(r"\.[a-z0-9]+$", "", fn)
    w = q["question"].replace(fn, "<F>").replace(stem, "<S>") if fn else q["question"]
    f = q.get("answer_format") or {}
    fv = json.dumps(f.get("accepted_values")) if f.get("accepted_values") else (f.get("syntax") or "")
    g.setdefault((shape(a), w, f.get("kind", ""), fv), []).append(a)
p("MISSING GROUPS:", len(g))
for (sh, w, fk, fv), ids in sorted(g.items(), key=lambda kv: -len(kv[1])):
    exts = sorted(set(os.path.splitext((qs[i].get("artifact") or "").split("->")[-1].strip())[1] for i in ids))
    p("")
    p("## %-44s n=%-4d ext=%s  e.g. %s" % (sh, len(ids), ",".join(exts), ids[0]))
    p("   Q:", w)
    p("   F:", fk, "|", fv[:500])
if out is not sys.stdout:
    out.close()
    print("wrote", sys.argv[2], "missing", len(miss), "groups", len(g))
