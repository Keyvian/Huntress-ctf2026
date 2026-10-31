"""Day-31 'No Artifact Left Behind' graph analyser for case-NNN.zip (artifacts/<id>, extensionless, typed by bytes).
Edges come from each member's own format: PowerShell launch line, JSON "next", e-mail route.txt attachment, nested zip run.txt,
SQLite launch_queue.target, PNG tEXt Comment next=. graph.execution_chain_artifact_ids = the path from the entry nothing references
down to a terminal member; the closed cycle that fills the rest of the case has no entry and is the decoy.
Mentions outside the edge-bearing field (comments, readme, notes, subjects) are reported as STRAY, not followed.
usage: graph31.py <case.zip>"""
import sys, io, re, json, zlib, struct, sqlite3, tempfile, os, email
import pyzipper

ID_RE = r"[a-z]+-[0-9a-f]{4,}"


def zmembers(b):
    z = pyzipper.AESZipFile(io.BytesIO(b))
    z.setpassword(b"infected")
    return z, [i for i in z.infolist() if not i.filename.endswith("/")]


def png_texts(d):
    p, out = 8, []
    while p + 8 <= len(d):
        n, t = struct.unpack(">I4s", d[p:p + 8])
        c = d[p + 8:p + 8 + n]
        if t == b"tEXt":
            out.append(c.split(b"\0", 1)[-1].decode("utf-8", "replace"))
        elif t == b"zTXt":
            k, rest = c.split(b"\0", 1)
            out.append(zlib.decompress(rest[1:]).decode("utf-8", "replace"))
        elif t == b"iTXt":
            parts = c.split(b"\0", 5)
            out.append(parts[-1].decode("utf-8", "replace"))
        p += 12 + n
    return out


def sqlite_rows(d):
    fd, fn = tempfile.mkstemp(suffix=".db")
    os.write(fd, d)
    os.close(fd)
    rows = []
    try:
        c = sqlite3.connect("file:%s?mode=ro&immutable=1" % fn, uri=True)
        tabs = [r[0] for r in c.execute("select name from sqlite_master where type='table'")]
        for t in tabs:
            cur = c.execute('select * from "%s"' % t)
            cols = [x[0] for x in cur.description]
            for r in cur:
                rows.append((t, dict(zip(cols, r))))
        c.close()
    finally:
        os.unlink(fn)
    return rows


def classify(b):
    if b[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if b[:15] == b"SQLite format 3":
        return "sqlite"
    if b[:4] == b"PK\x03\x04":
        return "zip"
    if b[:5] == b"From:" or b"\nMessage-ID:" in b[:400]:
        return "eml"
    s = b.lstrip()
    if s[:1] == b"{":
        return "json"
    if s[:1] == b"#" or b"$ErrorActionPreference" in b[:200]:
        return "ps1"
    return "other"


def extract(b):
    """-> kind, edge text (what the format says happens next), other text (mentions that do not drive execution), terminal marker"""
    k = classify(b)
    edge, other, term = [], [], None
    if k == "png":
        for t in png_texts(b):
            if t.startswith("next="):
                edge.append(t[5:].strip())
            elif t.startswith("done"):
                term = t.strip()
            else:
                other.append(t)
    elif k == "sqlite":
        rows = sqlite_rows(b)
        for t, r in rows:
            for c, v in r.items():
                (edge if c == "target" else other).append(str(v))
        if not edge and any(t == "summary" for t, _ in rows):
            term = "sqlite summary table"
    elif k == "zip":
        z, ms = zmembers(b)
        names = [os.path.basename(i.filename) for i in ms]
        for i in ms:
            t = z.read(i.filename).decode("utf-8", "replace")
            (edge if os.path.basename(i.filename) == "run.txt" else other).append(t)
        if "run.txt" not in names and "summary.txt" in names:
            term = "zip summary.txt"
    elif k == "eml":
        m = email.message_from_bytes(b)
        other += [str(m[h]) for h in ("Subject", "Message-ID", "From", "To")]
        for p in m.walk():
            if p.get_content_maintype() == "multipart":
                continue
            t = p.get_payload(decode=True).decode("utf-8", "replace")
            (edge if p.get_filename() else other).append(t)
        if not m.is_multipart():
            term = "eml without attachment"
    elif k == "json":
        o = json.loads(b.decode("utf-8", "replace"))
        for c, v in o.items():
            (edge if c == "next" else other).append(str(v))
        if o.get("done") is True:
            term = "json done"
    elif k == "ps1":
        for ln in b.decode("utf-8", "replace").splitlines():
            if ln.lstrip().startswith("#"):
                if "terminal" in ln:
                    term = ln.strip()
                other.append(ln)
            else:
                edge.append(ln)
    else:
        other.append(b.decode("latin1"))
    return k, edge, other, term


def analyse(b):
    z, ms = zmembers(b)
    nodes = {}
    for i in ms:
        nid = os.path.basename(i.filename)
        if i.filename.endswith(".json") and "manifest" in i.filename:
            print("  CASE MANIFEST", i.filename, z.read(i.filename)[:200])
            continue
        nodes[nid] = z.read(i.filename)
    ids = set(nodes)
    g, kinds, term, stray = {}, {}, {}, {}
    for n, d in nodes.items():
        k, edge, other, t = extract(d)
        kinds[n] = k
        term[n] = t
        g[n] = [x for x in dict.fromkeys(re.findall(ID_RE, "\n".join(edge))) if x in ids and x != n]
        unknown = [x for x in re.findall(ID_RE, "\n".join(edge)) if x not in ids]
        if unknown:
            print("  DANGLING", n, k, unknown)
        s = [x for x in re.findall(ID_RE, "\n".join(other)) if x in ids and x != n]
        if s:
            stray[n] = s
    return nodes, g, kinds, term, stray


def chains(g, term):
    indeg = {n: 0 for n in g}
    for n, o in g.items():
        for x in o:
            indeg[x] += 1
    roots = [n for n in g if indeg[n] == 0]
    out = []
    for r in roots:
        path, cur, why = [r], r, None
        while True:
            nx = g[cur]
            if len(nx) > 1:
                why = "branch at %s %s" % (cur, nx)
                break
            if not nx:
                why = "terminal" if term[cur] else "dead end"
                break
            if nx[0] in path:
                why = "loop back to %s" % nx[0]
                break
            path.append(nx[0])
            cur = nx[0]
        out.append((path, why))
    return roots, indeg, out


def field(b, name, verbose=False):
    if name != "execution_chain_artifact_ids":
        raise KeyError("graph." + name)
    nodes, g, kinds, term, stray = analyse(b)
    roots, indeg, res = chains(g, term)
    good = [p for p, w in res if w == "terminal"]
    covered = {n for p, _ in res for n in p}
    rest = [n for n in g if n not in covered]
    # every other member must sit on a closed cycle: no fork, no merge, no second exit, or the "one chain + decoy loop" reading fails
    fork = [n for n in g if len(g[n]) > 1] + [n for n, c in indeg.items() if c > 1]
    if fork or any(not g[n] for n in rest):
        raise ValueError("graph is not one chain plus cycles: fork/merge %s, loose ends %s" % (fork, [n for n in rest if not g[n]]))
    if verbose or len(good) != 1 or len(res) != 1 or stray:
        print("  GRAPH nodes %d roots %s stray %s" % (len(nodes), roots, stray))
        for p, w in res:
            print("   ", len(p), w, p)
        print("    uncovered (cycles)", len(rest), rest[:6])
    if len(good) != 1:
        raise ValueError("no unique rooted chain: " + repr(res))
    return good[0]


if __name__ == "__main__":
    b = open(sys.argv[1], "rb").read()
    nodes, g, kinds, term, stray = analyse(b)
    for n in g:
        print("%-16s %-7s -> %s %s" % (n, kinds[n], g[n], term[n] or ""))
    print(json.dumps(field(b, "execution_chain_artifact_ids", True), separators=(",", ":")))
