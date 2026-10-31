"""usage: qdiff.py <old start.json> <new start.json>  -> diff question ids/wording"""
import json, sys
a = json.load(open(sys.argv[1]))
b = json.load(open(sys.argv[2]))
ia = {q["id"]: q for q in a["questions"]}
ib = {q["id"]: q for q in b["questions"]}
print("old", len(ia), "new", len(ib), "common", len(set(ia) & set(ib)))
new = [k for k in ib if k not in ia]
print("NEW:", len(new))
for k in new:
    q = ib[k]
    print("  %-60s | %-40s | %s | %s" % (k, q.get("artifact", "")[-40:], q["question"][:140], json.dumps(q.get("answer_format"))[:160]))
gone = [k for k in ia if k not in ib]
print("GONE:", len(gone), gone[:40])
ch = [k for k in ib if k in ia and (ia[k]["question"] != ib[k]["question"] or ia[k].get("artifact") != ib[k].get("artifact"))]
print("CHANGED:", len(ch))
for k in ch[:40]:
    print("  ", k, "|", ia[k].get("artifact"), "->", ib[k].get("artifact"), "|", ib[k]["question"][:100])
