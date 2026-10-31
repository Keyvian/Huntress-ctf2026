"""Day-29 metadata 'Trust Issues' solver = m28 (Day 1-28 cumulative contract incl. pcap.*, disk.*) + x509.<field> for
certificates (x509.py: PEM/DER, fingerprints = hash of the DER). Same CLI as m28 (runs its __main__ via runpy):
usage: m29.py <challenge> [start|retry|practice|none] [--submit] [--partial] [--dir cached] [--save outdir]
       [--override id=value ...]      offline: m29.py x none --dir <saved dir>"""
import sys, os, re, runpy
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import m15, m28, x509

X509_RE = re.compile(r"(?:x509|certificate|cert)\.(\w+)")
_m28_field = m28.field_value
_m28_pcap_re = m28.PCAP_RE


def field_value(fld, b):
    mo = X509_RE.fullmatch(fld or "")
    if mo:
        return x509.field(b, mo.group(1))
    return _m28_field(fld, b)


# m28.solve re-resolves every question whose field matches m28.PCAP_RE through m28.field_value; widen both.
m28.PCAP_RE = re.compile(r"(?:pcap|pcapng|capture|disk|x509|certificate|cert)\.(\w+)")
m28.field_value = field_value
m15.field_value = field_value
_orig_solve28 = m28.solve


def solve(st, files):
    import json
    ans, unk = _orig_solve28(st, files)
    for q in st["questions"]:
        mo = re.search(r"Determine ((?:x509|certificate|cert)\.\w+) for", q["question"])
        if not mo or q["id"] in ans:
            continue
        m = re.match(r"set(\d+)\.", q["id"])
        setno = int(m.group(1)) if m else q.get("set")
        p, b = m15.find_member(files, q.get("artifact") or "", setno)
        if b is None:
            unk.append((q["id"], mo.group(1), "NOFILE " + str(q.get("artifact"))))
            continue
        try:
            v = field_value(mo.group(1), b)
            if isinstance(v, bool):
                v = "true" if v else "false"
            elif isinstance(v, (list, dict)):
                v = json.dumps(v, separators=(",", ":"), ensure_ascii=False)
            ans[q["id"]] = str(v)
        except Exception as ex:
            unk.append((q["id"], mo.group(1), p, repr(ex)))
    return ans, unk


m28.solve = solve

if __name__ == "__main__":
    src = open(m28.__file__).read().split('if __name__ == "__main__":', 1)[1]
    g = dict(vars(m28))
    g["solve"] = solve
    exec(compile("if True:" + src, m28.__file__, "exec"), g)
