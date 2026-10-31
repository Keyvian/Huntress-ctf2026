"""usage: sufmap.py <dir> -> one line per (id-suffix, wording) pair across the whole contract."""
import sys, os, json, re, collections

st = json.load(open(os.path.join(sys.argv[1], "start.json")))
g = collections.defaultdict(lambda: collections.defaultdict(int))
fmt = {}
for q in st["questions"]:
    i = re.sub(r"^set\d+\.", "", q["id"])
    fn = (q.get("artifact") or "").split("->")[-1].strip()
    stem = re.sub(r"\.[a-z0-9]+$", "", fn)
    # suffix = the part of the id AFTER the specimen token (file stem / 6-hex hash)
    if stem and ("-" + stem + "-") in i:
        suf = i.split("-" + stem + "-", 1)[1]
    else:
        m = re.search(r"-(?:[0-9a-f]{6,8})-(.*)$", i)
        suf = m.group(1) if m else i
    w = q["question"]
    if fn:
        w = w.replace(fn, "<F>").replace(stem, "<S>")
    g[suf][w] += 1
    f = q.get("answer_format") or {}
    fmt.setdefault(suf, f.get("kind", ""))
for suf in sorted(g):
    tot = sum(g[suf].values())
    print("== %-18s n=%-4d fmt=%s" % (suf, tot, fmt[suf]))
    for w, c in sorted(g[suf].items(), key=lambda kv: -kv[1]):
        print("   (%d) %s" % (c, w[:260]))
