"""Print the delivery manifest of a saved Seeing Double cluster. usage: peek30b.py <dir> [cluster member name]"""
import sys, os, io, json, zipfile

d = sys.argv[1]
z = zipfile.ZipFile(io.BytesIO(open(os.path.join(d, "artifact.bin"), "rb").read()))
name = sys.argv[2] if len(sys.argv) > 2 else z.namelist()[0]
c = zipfile.ZipFile(io.BytesIO(z.read(name)))
m = json.loads(c.read("delivery-manifest.json"))
print({k: (v if not isinstance(v, list) else "list[%d]" % len(v)) for k, v in m.items()})
for a in m["artifacts"]:
    print(json.dumps(a, separators=(",", ":")))
for k, v in m.items():
    if k not in ("artifacts", "schema"):
        print(k, json.dumps(v)[:3000])
