"""usage: contract.py <dir> [outfile]
Compact dump of a start.json question contract: group by (id-prefix, id-suffix), one block per
distinct question wording (filename substituted by <F>), with answer_format and example ids."""
import sys, os, json, re, collections

dd = sys.argv[1]
st = json.load(open(os.path.join(dd, "start.json")))
qs = st["questions"]
out = open(sys.argv[2], "w", encoding="utf-8") if len(sys.argv) > 2 else sys.stdout


def p(*a):
    print(*a, file=out)


p("mode", st.get("mode"), "nq", len(qs), "deadline", st.get("deadline"),
  "uar", st.get("unique_attempts_remaining"), "regvar", st.get("regular_variants_remaining"),
  "fresh", st.get("variant_fresh"), "rft", st.get("run_for_time"))

pref = collections.Counter()
for q in qs:
    pref[re.sub(r"^set\d+\.", "", q["id"]).split("-")[0]] += 1
p("PREFIX COUNTS:", dict(pref.most_common()))

groups = collections.OrderedDict()
for q in qs:
    i = re.sub(r"^set\d+\.", "", q["id"])
    fn = (q.get("artifact") or "").split("->")[-1].strip()
    stem = re.sub(r"\.[a-z0-9]+$", "", fn)
    # id = <prefix>-<specimen>-<suffix...>; specimen token is the file stem when present
    sid = i.replace(stem + "-", "-", 1) if stem and (stem + "-") in i else i
    key = re.sub(r"--+", "-", sid)
    w = q["question"]
    if fn:
        w = w.replace(fn, "<F>").replace(stem, "<S>")
    f = q.get("answer_format") or {}
    fk = f.get("kind", "")
    fv = json.dumps(f.get("accepted_values")) if f.get("accepted_values") else (f.get("syntax") or "")
    groups.setdefault((key, w, fk, fv), []).append(q["id"])

p("GROUPS:", len(groups))
for (key, w, fk, fv), ids in groups.items():
    p("")
    p("## %s   n=%d  e.g. %s" % (key, len(ids), ids[0]))
    p("   EXT:", sorted(set(os.path.splitext((q.get("artifact") or "").split("->")[-1].strip())[1]
                            for q in qs if q["id"] in set(ids[:40]))))
    p("   Q:", w)
    p("   F:", fk, "|", fv[:400])
if out is not sys.stdout:
    out.close()
    print("wrote", sys.argv[2], "groups", len(groups))
