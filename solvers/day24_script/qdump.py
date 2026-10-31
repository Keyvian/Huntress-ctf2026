"""usage: qdump.py <dir>  -> prompt/guidance, zip listing, questions grouped by artifact"""
import sys, json, os, collections, io
import pyzipper
d = sys.argv[1]
st = json.load(open(os.path.join(d, "start.json")))
print("NAME:", st.get("name"))
print("PROMPT:", st.get("prompt"))
print("GUIDANCE:", json.dumps(st.get("guidance"), indent=1)[:3000])
z = pyzipper.AESZipFile(os.path.join(d, "artifact.bin"))
z.setpassword(b"infected")
for i in z.infolist():
    print("  ZIP", i.filename, i.file_size)
by = collections.OrderedDict()
for q in st["questions"]:
    by.setdefault(q.get("artifact"), []).append(q)
print("artifacts:", len(by))
seen_fmt = set()
for a, qs in by.items():
    print("=== %s (%d)" % (a, len(qs)))
    for q in qs:
        f = json.dumps(q.get("answer_format")) + json.dumps(q.get("normalization"))
        extra = {k: v for k, v in q.items() if k not in ("id", "question", "artifact", "answer_format", "normalization")}
        print("   %-55s | %s | %s %s" % (q["id"], q["question"][:150], f[:200] if f not in seen_fmt else "", json.dumps(extra) if extra else ""))
        seen_fmt.add(f)
