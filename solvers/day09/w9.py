"""Day-9 warmup 'Escape Room' solver: iteratively un-escape (JSON \\uXXXX, C/py escapes, HTML entities,
URL %XX) plus the classic base64/hex/rot13 layers, then take the slug from the final non-empty line.
usage: w9.py <challenge> [--submit] [--file path]"""
import sys, re, json, html, urllib.parse, codecs, base64, os, io, zipfile
sys.path.insert(0, "~/ctf")
from gm import GM

SLUG = re.compile(r"\b[a-z]+-[a-z]+-[a-z]+-\d{2}\b")


def step(s):
    t = s.strip()
    # JSON string literal
    if t.startswith('"') and t.endswith('"'):
        try:
            r = json.loads(t)
            if isinstance(r, str) and r != s:
                return r
        except Exception:
            pass
    if re.search(r"\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}|\\[0-7]{3}|\\n", t):
        try:
            r = codecs.decode(t.encode("latin-1", "backslashreplace"), "unicode_escape")
            if r != s:
                return r
        except Exception:
            pass
    if re.search(r"&(#\d+|#x[0-9a-fA-F]+|[a-z]+);", t):
        r = html.unescape(t)
        if r != s:
            return r
    if re.search(r"%[0-9a-fA-F]{2}", t):
        r = urllib.parse.unquote(t)
        if r != s:
            return r
    compact = re.sub(r"\s", "", t)
    if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", compact) and len(compact) >= 8:
        try:
            r = bytes.fromhex(compact).decode("utf-8")
            return r
        except Exception:
            pass
    if re.fullmatch(r"[A-Za-z0-9+/_-]+=*", compact) and len(compact) >= 8:
        try:
            r = base64.b64decode(compact.replace("-", "+").replace("_", "/") + "=" * (-len(compact) % 4)).decode("utf-8")
            if sum(c.isprintable() or c in "\r\n\t" for c in r) >= 0.95 * len(r):
                return r
        except Exception:
            pass
    return None


def decode(s):
    for _ in range(100):
        n = step(s)
        if n is None or n == s:
            break
        s = n
    return s


def slug_of(text):
    lines = [re.sub(r"^\s*\d+\t", "", l) for l in text.splitlines() if l.strip()]
    final = lines[-1] if lines else ""
    m = SLUG.search(final)
    if not m:
        rr = codecs.encode(final, "rot_13")
        m = SLUG.search(rr)
    return (m.group(0) if m else None), final


if __name__ == "__main__":
    ch = sys.argv[1]
    if "--file" in sys.argv:
        raw = open(sys.argv[sys.argv.index("--file") + 1], "rb").read()
        st = {"answer_ids": ["message"]}
    else:
        g = GM()
        st = g.start(ch)
        raw = g.artifact(ch)
    blobs = {}
    if raw[:2] == b"PK":
        z = zipfile.ZipFile(io.BytesIO(raw))
        for n in z.namelist():
            blobs[n] = z.read(n)
    else:
        blobs["blob.txt"] = raw
    aids = st.get("answer_ids") or ["message"]
    qs = {q["id"]: q for q in st.get("questions") or []}
    ans = {}
    names = list(blobs)
    for i, a in enumerate(aids):
        art = (qs.get(a) or {}).get("artifact")
        key = art if art in blobs else (names[i] if i < len(names) else names[0])
        dec = decode(blobs[key].decode("utf-8", "replace"))
        sl, final = slug_of(dec)
        print(a, key, "FINAL", repr(final[-200:]), "SLUG", sl)
        ans[a] = sl
    if "--submit" in sys.argv:
        r = GM().submit(ch, ans)
        print("SUBMIT", {k: r.get(k) for k in ("result", "flag", "error", "remaining")})
