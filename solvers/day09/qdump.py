import sys, json, collections
st = json.load(open(sys.argv[1]))
by = collections.OrderedDict()
for q in st["questions"]:
    by.setdefault(q.get("artifact", ""), []).append(q)
for art, qs in by.items():
    print("##", art, len(qs))
    for q in qs:
        af = q.get("answer_format", {})
        extra = af.get("accepted_values") or af.get("syntax", "")
        print("   %-48s | %s | %s | %s" % (q["id"], q["question"][:150], af.get("kind"), str(extra)[:150]))
