"""Independent mastery check for Day 31: unpack the saved bundle, re-run the blobs through warm31's solve_blob, and verify each slug
against the strict row 29 (rot13->base64), row 30 (double percent) and row 31 (base64->gunzip->base32) decodes, without going through
the template search.
usage: warm_check31.py <dir holding artifact.bin>"""
import sys, os, io, re, zipfile, codecs, base64, gzip, urllib.parse, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import warm31  # noqa: F401
import warm24

d = sys.argv[1]
blobs = {}


def walk(zb):
    z = zipfile.ZipFile(io.BytesIO(zb))
    for n in z.namelist():
        b = z.read(n)
        if b[:2] == b"PK":
            walk(b)
        else:
            blobs[n.split("/")[-1]] = b


walk(open(os.path.join(d, "artifact.bin"), "rb").read())
print("blobs", len(blobs))
out = os.path.join(d, "blobs")
os.makedirs(out, exist_ok=True)
for n, b in blobs.items():
    open(os.path.join(out, n), "wb").write(b)

warm24.learn_positions(list(blobs.values()))
T = "Nice work decoding this warmup! To solve, submit this exact answer to the Game Master: "
bad = []
nrows = collections.Counter()
words = [collections.Counter() for _ in range(3)]
slugs = collections.Counter()
for n in sorted(blobs):
    s = blobs[n].decode("utf-8", "replace")
    rows = [l for l in s.splitlines() if l.strip()]
    nrows[len(rows)] += 1
    labs = [l.split("\t", 1)[0] for l in rows]
    if labs != ["%02d" % i for i in range(1, len(rows) + 1)]:
        bad.append((n, "LABELS", labs[:4]))
    slug, msg = warm24.solve_blob(blobs[n])
    if not slug or not (msg or "").startswith(T) or msg[len(T):].rstrip(".") != slug:
        bad.append((n, "TEMPLATE", slug, (msg or "")[:100]))
        continue
    slugs[slug] += 1
    for i, w in enumerate(slug.split("-")[:3]):
        words[i][w] += 1
    r31 = base64.b32decode(gzip.decompress(base64.b64decode(rows[-1].split("\t", 1)[1]))).decode()
    r30 = urllib.parse.unquote(urllib.parse.unquote(rows[-2].split("\t", 1)[1]))
    r29 = base64.b64decode(codecs.decode(rows[-3].split("\t", 1)[1], "rot13")).decode()
    if not (msg + "\n").rstrip("\n").endswith(r29 + r30 + r31):
        bad.append((n, "TAIL", r29, r30, r31, slug))
print("row counts", dict(nrows))
print("bad", len(bad), bad[:10])
print("duplicate slugs", [k for k, v in slugs.items() if v > 1][:10])
for i in range(3):
    once = sorted(w for w, c in words[i].items() if c == 1)
    print("pos", i, "distinct", len(words[i]), "singletons", once[:40])
