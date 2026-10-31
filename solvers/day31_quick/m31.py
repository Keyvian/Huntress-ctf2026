"""Day-31 metadata 'No Artifact Left Behind' solver = m30 (Day 1-30 cumulative contract incl. relation.*) + graph.<field> for
case zips (graph31.py). Same CLI as m28 (runs its __main__):
usage: m31.py <challenge> [start|retry|practice|none] [--submit] [--partial] [--dir cached] [--save outdir]
       [--override id=value ...]      offline: m31.py x none --dir <saved dir>"""
import sys, os, re, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import m15, m28, m30, graph31

GRAPH_RE = re.compile(r"Determine (graph\.\w+) for")
_m30_solve = m30.solve


def solve(st, files):
    ans, unk = _m30_solve(st, files)
    unk = [u for u in unk if "graph." not in str(u[1])]
    for q in st["questions"]:
        mo = GRAPH_RE.search(q["question"])
        if not mo:
            continue
        m = re.match(r"set(\d+)\.", q["id"])
        setno = int(m.group(1)) if m else q.get("set")
        p, b = m15.find_member(files, q.get("artifact") or "", setno)
        if b is None:
            unk.append((q["id"], mo.group(1), "NOFILE " + str(q.get("artifact"))))
            continue
        try:
            ans[q["id"]] = json.dumps(graph31.field(b, mo.group(1).split(".", 1)[1]), separators=(",", ":"))
        except Exception as ex:
            unk.append((q["id"], mo.group(1), p, repr(ex)))
    return ans, unk


m28.solve = solve

if __name__ == "__main__":
    src = open(m28.__file__).read().split('if __name__ == "__main__":', 1)[1]
    g = dict(vars(m28))
    g["solve"] = solve
    exec(compile("if True:" + src, m28.__file__, "exec"), g)
