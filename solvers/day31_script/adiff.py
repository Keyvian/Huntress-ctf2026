"""usage: adiff.py <old dir> <new dir>  -> compare answers.json for the shared ids + hash-compare same-named specimens"""
import sys, os, json, hashlib, collections
o, n = sys.argv[1], sys.argv[2]
a = json.load(open(os.path.join(o, "answers.json")))
b = json.load(open(os.path.join(n, "answers.json")))
common = set(a) & set(b)
diff = [k for k in sorted(common) if a[k] != b[k]]
print("old", len(a), "new", len(b), "common", len(common), "differ", len(diff))
print(collections.Counter(k.rsplit("-", 1)[-1] for k in diff).most_common(30))
for k in diff[:25]:
    print("  %-60s %s -> %s" % (k, a[k][:50], b[k][:50]))


def hashes(d):
    out = {}
    for r, _, fs in os.walk(os.path.join(d, "x")):
        for f in fs:
            out[f] = hashlib.sha256(open(os.path.join(r, f), "rb").read()).hexdigest()
    return out


ha, hb = hashes(o), hashes(n)
same = [f for f in hb if ha.get(f) == hb[f]]
chg = [f for f in hb if f in ha and ha[f] != hb[f]]
print("files old", len(ha), "new", len(hb), "identical", len(same), "changed", len(chg), "new", len([f for f in hb if f not in ha]))
print("changed", chg[:40])
print("added", [f for f in hb if f not in ha][:40])
print("removed", [f for f in ha if f not in hb][:40])
