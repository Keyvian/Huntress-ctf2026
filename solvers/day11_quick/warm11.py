"""Day-11 warmup 'Safe Travels' (base64url) solver, all modes. Superset of warm10 (adds base64url).
usage: warm11.py <challenge> [op=start|retry|practice] [dry]
       warm11.py local <dir>"""
import sys, os, json, io, re, zipfile, base64, binascii, codecs, time, itertools, html, urllib.parse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gmx import GMX

SLUG = re.compile(r"\b([a-z]+-[a-z]+-[a-z]+-\d{2})\b")


def pad(s, n):
    s = s.rstrip("=")
    return s + "=" * (-len(s) % n)


def layers(s):
    """candidate decodings of a text blob (one layer)."""
    t = re.sub(r"^\d+\t", "", s.strip())
    c = re.sub(r"\s+", "", t)
    out = []
    if re.fullmatch(r"[A-Za-z0-9_\-]+=*", c):
        try: out.append(base64.urlsafe_b64decode(pad(c, 4)))
        except Exception: pass
    try: out.append(base64.b64decode(pad(c, 4), validate=True))
    except Exception: pass
    try: out.append(base64.b32decode(pad(c.upper(), 8)))
    except Exception: pass
    try: out.append(binascii.unhexlify(c))
    except Exception: pass
    out.append(codecs.encode(t, "rot13").encode())
    res = []
    for o in out:
        try: res.append(o.decode("utf-8"))
        except Exception: pass
    return res


def _pr(b):
    try: s = b.decode("ascii") if isinstance(b, bytes) else b
    except Exception: return None
    return s if s and all(32 <= ord(c) < 127 for c in s) else None


def line_decode(f):
    """decode one mixed-codec fragment; plausible decodings, best first."""
    f = f.rstrip("\r\n")
    out = []
    def add(x):
        x = _pr(x)
        if x is not None and x not in out: out.append(x)
    if f.startswith('"') and f.endswith('"') and "\\u" in f:
        try: add(json.loads(f))
        except Exception: pass
    if "&#" in f: add(html.unescape(f))
    if re.fullmatch(r"(%[0-9A-Fa-f]{2})+", f): add(urllib.parse.unquote(f))
    if re.fullmatch(r"[01]{8}( [01]{8})*", f): add(bytes(int(t, 2) for t in f.split()))
    if re.fullmatch(r"\d{1,3}( \d{1,3})*", f):
        toks = f.split()
        dec = None if any(int(t) > 255 for t in toks) else _pr(bytes(int(t) for t in toks))
        octv = None if re.search(r"[89]", f) else _pr(bytes(int(t, 8) for t in toks if int(t, 8) < 256))
        lead0 = any(len(t) > 1 and t[0] == "0" for t in toks)
        for x in ([octv, dec] if lead0 else [dec, octv]):
            if x is not None: add(x)
    if re.fullmatch(r"([0-9a-fA-F]{2})+", f): add(binascii.unhexlify(f))
    if re.fullmatch(r"[A-Z2-7]+=*", f):
        try: add(base64.b32decode(pad(f, 8)))
        except Exception: pass
    if re.fullmatch(r"[A-Za-z0-9_\-]+=*", f):
        try: add(base64.urlsafe_b64decode(pad(f, 4)))
        except Exception: pass
    if re.fullmatch(r"[A-Za-z0-9+/]+=*", f):
        try: add(base64.b64decode(pad(f, 4)))
        except Exception: pass
    add(codecs.encode(f, "rot13"))
    return out


TEMPLATE = re.compile(r"Game Master: ([a-z]+-[a-z]+-[a-z]+-\d{2})\.?$")


def solve_mixed(s):
    rows = []
    for l in s.splitlines():
        if not l.strip(): continue
        m = re.match(r"^(\d+)\t(.*)$", l)
        if not m: return None
        rows.append((int(m.group(1)), m.group(2)))
    rows.sort()
    cands = [line_decode(f) for _, f in rows]
    if any(not c for c in cands): return None
    fallback = None
    for combo in itertools.islice(itertools.product(*cands), 4096):
        msg = "".join(combo)
        m = TEMPLATE.search(msg)
        if m and msg.startswith("Nice work"): return m.group(1), msg
        if m and fallback is None: fallback = (m.group(1), msg)
    return fallback


def solve_blob(raw):
    s = raw.decode("utf-8", "replace")
    if re.match(r"^\d+\t", s) and len([l for l in s.splitlines() if l.strip()]) > 1:
        r = solve_mixed(s)
        if r: return r
    frontier = [s]
    for depth in range(10):
        nxt = []
        for x in frontier:
            lines = [l for l in x.splitlines() if l.strip()]
            if lines and "Game Master" in lines[-1]:
                m = SLUG.findall(lines[-1])
                if m: return m[-1], x
            nxt.extend(layers(x))
        frontier = [n for n in nxt if n and sum(ch.isprintable() or ch in "\r\n\t" for ch in n) > 0.95 * len(n)]
        if not frontier: break
    return None, s


def main():
    ch = sys.argv[1]
    if ch == "local":
        d = sys.argv[2]
        for fn in sorted(os.listdir(d)):
            slug, msg = solve_blob(open(os.path.join(d, fn), "rb").read())
            print(fn, slug, "|", (msg or "")[:160].replace("\n", " "))
        return
    op = sys.argv[2] if len(sys.argv) > 2 else "start"
    dry = len(sys.argv) > 3 and sys.argv[3] == "dry"
    save = os.environ.get("SAVE")
    g = GMX()
    t0 = time.time()
    r = g.post({"op": op, "challenge": ch})
    ids = r.get("answer_ids"); qs = r.get("questions") or []
    print("mode", r.get("mode"), "deadline", r.get("deadline"), "uar", r.get("unique_attempts_remaining"),
          "nids", len(ids or []), "err", r.get("error"))
    if not ids:
        print(json.dumps({k: v for k, v in r.items() if k != "guidance"})[:3000]); return
    b = g.artifact(ch)
    if save:
        os.makedirs(save, exist_ok=True)
        open(os.path.join(save, "artifact.bin"), "wb").write(b)
        json.dump(r, open(os.path.join(save, "start.json"), "w"))
    files = {}
    if b[:2] == b"PK":
        def walk(zb):
            z = zipfile.ZipFile(io.BytesIO(zb))
            for n in z.namelist():
                d = z.read(n)
                if d[:2] == b"PK": walk(d)
                else: files[n.split("/")[-1]] = d
        walk(b)
    else:
        files[qs[0]["artifact"] if qs else "blob.txt"] = b
    print("files", len(files), list(files)[:6])
    ans = {}
    for q in qs:
        if q["id"] in ids:
            cand = [q["id"]]
        else:
            st = q.get("set")
            cand = [a for a in ids if a in ("set%s.%s" % (st, q["id"]), "%s.%s" % (st, q["id"]))]
        art = q.get("artifact")
        data = files.get(art)
        if data is None and len(files) == 1:
            data = list(files.values())[0]
        slug, dec = solve_blob(data) if data is not None else (None, "")
        print(q.get("set"), q["id"], art, "->", slug, "|", (dec or "")[-90:].replace("\n", " "))
        if slug and cand:
            ans[cand[0]] = slug
    print("compute %.2fs" % (time.time() - t0))
    if len(ans) != len(ids):
        print("ABORT: answers", len(ans), "of", len(ids), "- not submitting")
        return
    if dry: return
    res = g.submit(ch, ans)
    print("SUBMIT", json.dumps(res)[:1500], "%.2fs" % (time.time() - t0))


main()
