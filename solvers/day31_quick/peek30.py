"""Dump a saved Seeing Double metadata artifact: nested zip tree with sizes/sha256/heads. usage: peek30.py <dir>"""
import sys, os, io, json, zipfile, hashlib

d = sys.argv[1]
st = json.load(open(os.path.join(d, "start.json")))
print({k: v for k, v in st.items() if k not in ("guidance", "questions")})
for q in st["questions"][:60]:
    print(q["id"], "|", q["question"][:160], "|", q.get("artifact"), "|", q.get("answer_format"), "|", q.get("normalization"))


def walk(zb, pre, depth=0):
    z = zipfile.ZipFile(io.BytesIO(zb))
    print(" " * depth + "ZIP %s comment=%r entries=%d" % (pre, z.comment, len(z.infolist())))
    for i in z.infolist():
        b = z.read(i.filename)
        print(" " * depth + "  %-46s size=%-7d comp=%-7d m=%d t=%s crc=%08x extra=%r cmt=%r sha=%s" % (
            i.filename, len(b), i.compress_size, i.compress_type, i.date_time, i.CRC, i.extra[:16], i.comment, hashlib.sha256(b).hexdigest()[:16]))
        if b[:2] == b"PK":
            walk(b, pre + "/" + i.filename, depth + 2)
        else:
            print(" " * depth + "      head=%r" % b[:260])


walk(open(os.path.join(d, "artifact.bin"), "rb").read(), "artifact")
