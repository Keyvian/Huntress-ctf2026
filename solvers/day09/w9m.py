"""Day-9 warmup 'Escape Room' mastery/any-mode solver.
Each blob = numbered lines 'NN\\t<fragment>', every fragment in its own encoding
(base64, rot13, hex, binary, decimal, octal, %XX, &#NN;, JSON \\uXXXX). Decode each, concatenate in NN order,
take the slug from the final line.  usage: w9m.py <challenge> [--submit] [--dir extracted_dir]"""
import sys, re, json, html, urllib.parse, codecs, base64, os, io, zipfile, string
sys.path.insert(0, "~/ctf")
from gm import GM

SLUG = re.compile(r"[a-z]+-[a-z]+-[a-z]+-\d{2}")
GOOD = set(string.ascii_letters + string.digits + " .,:;!?'-\"()")


def score(t):
    if t is None or t == "":
        return -1e9
    return sum((c in GOOD) * (2 if c.islower() or c == " " else 1) for c in t) / len(t) - sum(not c.isprintable() for c in t) * 5


def cands(f):
    out = []
    s = f
    t = s.strip()
    if t.startswith('"') and t.endswith('"'):
        try:
            out.append(("json", json.loads(t)))
        except Exception:
            pass
    if "\\u" in t or "\\x" in t:
        try:
            out.append(("uesc", codecs.decode(t, "unicode_escape")))
        except Exception:
            pass
    if re.search(r"%[0-9a-fA-F]{2}", t):
        out.append(("url", urllib.parse.unquote(t)))
    if re.search(r"&#?\w+;", t):
        out.append(("html", html.unescape(t)))
    toks = t.split()
    if toks and all(re.fullmatch(r"[01]{8}", x) for x in toks):
        out.append(("bin", "".join(chr(int(x, 2)) for x in toks)))
    if toks and all(x.isdigit() for x in toks):
        try:
            out.append(("dec", "".join(chr(int(x)) for x in toks)))
        except Exception:
            pass
        if all(re.fullmatch(r"[0-7]+", x) for x in toks):
            try:
                out.append(("oct", "".join(chr(int(x, 8)) for x in toks)))
            except Exception:
                pass
    if toks and all(re.fullmatch(r"0x[0-9a-fA-F]{2}|\\x[0-9a-fA-F]{2}", x) for x in toks):
        out.append(("hext", "".join(chr(int(x[2:], 16)) for x in toks)))
    c = re.sub(r"\s", "", t)
    if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", c):
        try:
            out.append(("hex", bytes.fromhex(c).decode("utf-8")))
        except Exception:
            pass
    if re.fullmatch(r"[A-Za-z0-9+/_-]+=*", c):
        try:
            out.append(("b64", base64.b64decode(c.replace("-", "+").replace("_", "/") + "=" * (-len(c) % 4)).decode("utf-8")))
        except Exception:
            pass
    if re.fullmatch(r"[A-Z2-7]+=*", c):
        try:
            out.append(("b32", base64.b32decode(c + "=" * (-len(c) % 8)).decode("utf-8")))
        except Exception:
            pass
    out.append(("rot13", codecs.encode(s, "rot_13")))
    out.append(("plain", s))
    return out


def decode_frag(f):
    cs = cands(f)
    # json/url/html/bin/dec/oct/hex are structural: if present prefer best-scoring among them
    best = max(cs, key=lambda kv: (score(kv[1]) + (0.3 if kv[0] not in ("rot13", "plain", "b64", "b32") else 0)
                                   + (0.15 if kv[0] == "b64" else 0)))
    return best


def decode_blob(text):
    frags = []
    for ln in text.splitlines():
        if not ln.strip():
            continue
        m = re.match(r"^\s*(\d+)\t(.*)$", ln)
        if m:
            frags.append((int(m.group(1)), m.group(2)))
        else:
            frags.append((len(frags) + 1, ln))
    frags.sort(key=lambda x: x[0])
    parts = []
    for n, f in frags:
        k, v = decode_frag(f)
        parts.append((k, v))
    return "".join(v for k, v in parts), [k for k, v in parts]


def slug_of(dec):
    lines = [l for l in dec.splitlines() if l.strip()]
    final = lines[-1] if lines else ""
    m = re.search(r"Game Master:\s*(" + SLUG.pattern + r")", final) or SLUG.search(final)
    return (m.group(1) if m and m.groups() else (m.group(0) if m else None)), final


def gather(raw):
    blobs = {}
    if raw[:2] == b"PK":
        z = zipfile.ZipFile(io.BytesIO(raw))
        for n in z.namelist():
            d = z.read(n)
            if d[:2] == b"PK":
                for k, v in gather(d).items():
                    blobs[k] = v
            else:
                blobs[os.path.basename(n)] = d
    else:
        blobs["blob.txt"] = raw
    return blobs


if __name__ == "__main__":
    ch = sys.argv[1]
    if "--dir" in sys.argv:
        dd = sys.argv[sys.argv.index("--dir") + 1]
        blobs = {n: open(os.path.join(dd, n), "rb").read() for n in sorted(os.listdir(dd))}
        st = {"answer_ids": ["set%d.message" % (i + 1) for i in range(len(blobs))],
              "questions": [{"id": "set%d.message" % (i + 1), "artifact": n} for i, n in enumerate(sorted(blobs))]}
    else:
        g = GM()
        st = g.start(ch)
        blobs = gather(g.artifact(ch))
    aids = st.get("answer_ids") or ["message"]
    qs = {q["id"]: q for q in st.get("questions") or []}
    names = sorted(blobs)
    ans = {}
    bad = 0
    for i, a in enumerate(aids):
        art = (qs.get(a) or {}).get("artifact")
        key = art if art in blobs else names[min(i, len(names) - 1)]
        dec, kinds = decode_blob(blobs[key].decode("utf-8", "replace"))
        sl, final = slug_of(dec)
        ok = bool(sl) and "submit this exact answer to the Game Master" in final
        bad += not ok
        print(a, key, sl, "OK" if ok else "??", kinds if not ok or i < 2 else "", repr(final) if not ok or i < 2 else "")
        ans[a] = sl or ""
    print("BAD", bad, "of", len(aids))
    if "--submit" in sys.argv and bad == 0:
        r = GM().submit(ch, ans)
        print("SUBMIT", {k: r.get(k) for k in ("result", "flag", "error", "remaining")})
