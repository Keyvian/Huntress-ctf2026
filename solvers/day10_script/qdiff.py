import json, sys
a = json.load(open("~/d9/scr_s/start.json"))
b = json.load(open(sys.argv[1]))
ia = {q["id"]: q for q in a["questions"]}
ib = {q["id"]: q for q in b["questions"]}
print("d9", len(ia), "d10", len(ib), "common", len(set(ia) & set(ib)))
new = [k for k in ib if k not in ia]
print("NEW in d10:", len(new))
for k in new:
    q = ib[k]
    print("  %-60s | %-40s | %s | %s" % (k, q.get("artifact", "")[-40:], q["question"][:140], json.dumps(q.get("answer_format"))[:160]))
gone = [k for k in ia if k not in ib]
print("GONE from d9:", len(gone), gone[:40])
# questions whose text changed
ch = [k for k in ib if k in ia and (ia[k]["question"] != ib[k]["question"] or ia[k].get("artifact") != ib[k].get("artifact"))]
print("CHANGED:", len(ch))
for k in ch[:40]:
    print("  ", k, "|", ia[k].get("artifact"), "->", ib[k].get("artifact"), "|", ib[k]["question"][:100])
