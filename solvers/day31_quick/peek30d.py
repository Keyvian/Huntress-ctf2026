"""Raw listing of a cluster zip (no manifest assumptions, CRC failures tolerated). usage: peek30d.py <dir> [cluster name] [maxlines]"""
import sys, os, io, zipfile, hashlib, collections, struct

d = sys.argv[1]
name = sys.argv[2] if len(sys.argv) > 2 else "cluster-001.zip"
mx = int(sys.argv[3]) if len(sys.argv) > 3 else 400
z = zipfile.ZipFile(io.BytesIO(open(os.path.join(d, "artifact.bin"), "rb").read()))
c = zipfile.ZipFile(io.BytesIO(z.read(name)))
print("comment", c.comment, "entries", len(c.infolist()))
n = 0
by = collections.defaultdict(list)
for i in c.infolist():
    raw = None
    err = None
    try:
        raw = c.read(i.filename)
    except Exception as ex:
        err = repr(ex)[:60]
        # stored member: take the local-file data directly so the bad CRC member is still inspectable
        fp = c.fp
        fp.seek(i.header_offset)
        h = fp.read(30)
        nl, el = struct.unpack("<HH", h[26:30])
        fp.seek(i.header_offset + 30 + nl + el)
        raw = fp.read(i.compress_size)
    sha = hashlib.sha256(raw).hexdigest()
    by[sha].append(i.filename)
    n += 1
    if n <= mx:
        print("%-46s sz=%-6d cmp=%-6d m=%d t=%s crc=%08x fl=%x cmt=%r sha=%s %s %r" % (
            i.filename, i.file_size, i.compress_size, i.compress_type, i.date_time, i.CRC, i.flag_bits, i.comment, sha[:10], err or "", raw[:96]))
print("distinct sha", len(by), sorted(len(v) for v in by.values()))
for k, v in sorted(by.items(), key=lambda t: -len(t[1]))[:14]:
    print(k[:12], len(v), v[:7])
