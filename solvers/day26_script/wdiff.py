"""usage: wdiff.py <old start.json> <new start.json>
Diff the question CONTRACT by (normalized id shape, wording) rather than by exact id, so two
different variants of the same challenge can be compared (specimen hashes differ per variant)."""
import sys, json, re, collections


def shapes(path):
    st = json.load(open(path))
    out = collections.defaultdict(list)
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
        fv = json.dumps(f.get("accepted_values")) if f.get("accepted_values") else (f.get("syntax") or "")
        out[sh].append((w, f.get("kind", ""), fv))
    return {k: (v[0], len(v)) for k, v in out.items()}


a, b = shapes(sys.argv[1]), shapes(sys.argv[2])
print("old shapes", len(a), "new shapes", len(b))
new = [k for k in b if k not in a]
gone = [k for k in a if k not in b]
chg = [k for k in b if k in a and a[k][0] != b[k][0]]
print("\nNEW SHAPES:", len(new))
for k in sorted(new):
    print("  %-46s n=%-4d %s" % (k, b[k][1], b[k][0][0][:220]))
print("\nGONE SHAPES:", len(gone))
for k in sorted(gone):
    print("  %-46s n=%d" % (k, a[k][1]))
print("\nREWORDED:", len(chg))
for k in sorted(chg):
    print("  ##", k, "n=%d->%d" % (a[k][1], b[k][1]))
    print("     OLD:", a[k][0][0][:300])
    print("     NEW:", b[k][0][0][:300])
    if a[k][0][1:] != b[k][0][1:]:
        print("     FMT:", a[k][0][1:], "->", b[k][0][1:])
