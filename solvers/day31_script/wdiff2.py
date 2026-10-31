"""usage: wdiff2.py <old start.json> <new start.json>
Stricter timed-contract diff than wdiff.py: per normalized shape, report only REAL changes (question text,
answer kind, accepted_values) and list the distinct `syntax` strings on both sides, so a pure format-hint
rewrite cannot hide a convention change."""
import sys, json, re, collections


def shapes(path):
    st = json.load(open(path))
    out = collections.defaultdict(list)
    syn = collections.Counter()
    for q in st["questions"]:
        i = re.sub(r"^set\d+\.", "", q["id"])
        fn = (q.get("artifact") or "").split("->")[-1].strip()
        stem = re.sub(r"\.[a-z0-9]+$", "", fn)
        sh = i.replace("-" + stem, "-*", 1) if stem and ("-" + stem) in i else i
        sh = re.sub(r"-(?:[0-9a-f]{6,8})-", "-*-", sh)
        w = q["question"]
        if fn:
            w = w.replace(fn, "<F>").replace(stem, "<S>")
        f = q.get("answer_format") or {}
        syn[(f.get("kind"), f.get("syntax"))] += 1
        extra = {k: v for k, v in f.items() if k not in ("kind", "syntax", "accepted_values")}
        out[sh].append((w, f.get("kind", ""), json.dumps(f.get("accepted_values"), sort_keys=True), json.dumps(extra, sort_keys=True)))
    return out, syn


a, sa = shapes(sys.argv[1])
b, sb = shapes(sys.argv[2])
print("OLD syntax strings")
for k, v in sa.most_common():
    print("  %5d %s" % (v, k))
print("NEW syntax strings")
for k, v in sb.most_common():
    print("  %5d %s" % (v, k))
real = 0
for k in sorted(b):
    if k not in a:
        continue
    ua, ub = set(a[k]), set(b[k])
    if ua != ub:
        real += 1
        print("## REAL CHANGE", k, "n=%d->%d" % (len(a[k]), len(b[k])))
        for x in sorted(ua - ub):
            print("   OLD", tuple(str(y)[:420] for y in x))
        for x in sorted(ub - ua):
            print("   NEW", tuple(str(y)[:420] for y in x))
print("real changes:", real, "of", len(set(a) & set(b)), "shared shapes")
