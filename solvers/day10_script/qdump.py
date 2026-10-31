"""usage: qdump.py <dir>  -> prints zip listing + questions grouped by artifact"""
import sys, os, io, json, collections
import pyzipper
dd = sys.argv[1]
st = json.load(open(os.path.join(dd, "start.json")))
z = pyzipper.AESZipFile(io.BytesIO(open(os.path.join(dd, "artifact.bin"), "rb").read()))
z.setpassword(b"infected")
print("ZIP members:")
for zi in z.infolist():
    print("  %-60s %7d" % (zi.filename, zi.file_size))
groups = collections.OrderedDict()
for q in st["questions"]:
    groups.setdefault(q.get("artifact"), []).append(q)
print("\nprompt:", st.get("prompt"))
for art, qs in groups.items():
    print("\n### artifact:", art, "(%d q)" % len(qs))
    for q in qs:
        af = q.get("answer_format")
        afs = json.dumps(af) if af else ""
        print("  %-62s | %s | %s | norm=%s" % (q["id"], q["question"][:150], afs[:200], q.get("normalization")))
