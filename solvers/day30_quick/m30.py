"""Day-30 metadata 'Seeing Double' solver = m29 (Day 1-29 cumulative contract incl. pcap.*, disk.*, x509.*) + relation.<field> for
cluster zips (rel30.py). relation.identical_sha256_groups = [[<artifact id>, ...], ...]: bytes hashed for real, members keyed by the
manifest id of their path (NOT the filename - the filename form is graded incorrect). Same CLI as m28 (runs its __main__):
usage: m30.py <challenge> [start|retry|practice|none] [--submit] [--partial] [--dir cached] [--save outdir]
       [--override id=value ...]      offline: m30.py x none --dir <saved dir>"""
import sys, os, io, re, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import m15, m28, m29, rel30

REL_RE = re.compile(r"Determine (relation\.\w+) for")
_m29_solve = m29.solve


def unzip_all(data, pfx=""):
    """m15.unzip_all, but a member that fails its CRC (seen deep inside a cluster's nested zips) is logged, not fatal: the outer
    artifact's own bytes are what get hashed, so an unreadable inner member only loses that member."""
    out = []
    try:
        zf = m15.pyzipper.AESZipFile(io.BytesIO(data)); zf.setpassword(b"infected")
        infos = zf.infolist()
    except Exception:
        return out
    for zi in infos:
        if zi.filename.endswith("/"):
            continue
        try:
            b = zf.read(zi.filename)
        except Exception as ex:
            print("  UNREADABLE MEMBER", pfx + zi.filename, repr(ex)[:90])
            continue
        p = pfx + zi.filename
        out.append((p, b))
        if b[:4] == b"PK\x03\x04":
            out += unzip_all(b, p + "/")
    return out


m15.unzip_all = unzip_all
m28.unzip_all = unzip_all


def solve(st, files):
    ans, unk = _m29_solve(st, files)
    unk = [u for u in unk if "relation." not in str(u[1])]
    for q in st["questions"]:
        mo = REL_RE.search(q["question"])
        if not mo:
            continue
        m = re.match(r"set(\d+)\.", q["id"])
        setno = int(m.group(1)) if m else q.get("set")
        p, b = m15.find_member(files, q.get("artifact") or "", setno)
        if b is None:
            unk.append((q["id"], mo.group(1), "NOFILE " + str(q.get("artifact"))))
            continue
        try:
            bad = rel30.check_manifest(b)
            if bad:
                print("  MANIFEST MISMATCH", q["id"], bad[:6])
            ans[q["id"]] = json.dumps(rel30.field(b, mo.group(1).split(".", 1)[1]), separators=(",", ":"))
        except Exception as ex:
            unk.append((q["id"], mo.group(1), p, repr(ex)))
    return ans, unk


m28.solve = solve

if __name__ == "__main__":
    src = open(m28.__file__).read().split('if __name__ == "__main__":', 1)[1]
    g = dict(vars(m28))
    g["solve"] = solve
    exec(compile("if True:" + src, m28.__file__, "exec"), g)
