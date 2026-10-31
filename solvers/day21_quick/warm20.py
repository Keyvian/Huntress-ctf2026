"""Day-20 warmup 'Big Entrance' ("Same bar. This time the big one goes first." = hex of UTF-16BE with BOM FE FF) solver, all modes.
Superset of warm19 (UTF-16) = warm18 (rail fence) = warm17 (Bacon) = warm16 (Morse) = warm15 (rot47) = warm14. Day-20 fixes:
 * solve_mixed(): mixed-codec NN\t rows are now combined by a TEMPLATE-GUIDED left-to-right search (the concatenation must stay a
   prefix of "Nice work decoding this warmup! To solve, submit this exact answer to the Game Master: " and then a slug), instead of
   the first 4096 combos of itertools.product (which never reached the right combination for 20-row blobs where the English
   scorer ranked letter-free garbage first) — the old product search is kept as a fallback.
 * eng_score(): strings with no letters score -9 (they used to score a perfect 0.0 and outrank real English).
 * solve_blob(): the multi-layer frontier is deduplicated and capped (it exploded to 7^10 strings / 1.8 GB when solve_mixed failed).
usage: warm20.py <challenge> [op=start|retry|practice] [dry]     (env SAVE=<dir> saves start.json+artifact)
       warm20.py local <dir>"""
import sys, os, json, io, re, zipfile, base64, binascii, codecs, time, itertools, html, urllib.parse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gmx import GMX

SLUG = re.compile(r"\b([a-z]+-[a-z]+-[a-z]+-\d{2})\b")

_AZ = "abcdefghijklmnopqrstuvwxyz"
ATBASH = str.maketrans(_AZ + _AZ.upper(), _AZ[::-1] + _AZ.upper()[::-1])

MORSE = {".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F", "--.": "G", "....": "H", "..": "I",
         ".---": "J", "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
         "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y", "--..": "Z",
         "-----": "0", ".----": "1", "..---": "2", "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
         "---..": "8", "----.": "9", ".-.-.-": ".", "--..--": ",", "..--..": "?", ".----.": "'", "-.-.--": "!",
         "-..-.": "/", "-.--.": "(", "-.--.-": ")", ".-...": "&", "---...": ":", "-.-.-.": ";", "-...-": "=",
         ".-.-.": "+", "-....-": "-", "..--.-": "_", ".-..-.": '"', "...-..-": "$", ".--.-.": "@"}
MORSE_RE = re.compile(r"^[.\-·•_–—−/|\s]+$")


def is_morse(s):
    return bool(s.strip()) and bool(MORSE_RE.match(s)) and ("." in s or "·" in s or "•" in s) and ("-" in s or "_" in s or "–" in s or "−" in s or "—" in s or re.search(r"\.\s", s))


def morse(s):
    """decode Morse text; words separated by '/', '|' or 3+ spaces; lines kept. Unknown tokens -> '?'."""
    s = s.translate(str.maketrans("·•_–—−|", "..----/"))
    out_lines = []
    for line in s.splitlines():
        if not line.strip():
            continue
        words = re.split(r"\s*/\s*|\s{3,}", line.strip())
        out_lines.append(" ".join("".join(MORSE.get(t, "?") for t in w.split()) for w in words if w.strip()))
    return "\n".join(out_lines)


# ---------------------------------------------------------------- Bacon cipher (day 17)
BACON_RE = re.compile(r"^[abAB\s]+$")
_B24 = "abcdefghiklmnopqrstuwxyz"  # 24-letter variant (i/j, u/v merged)


def is_bacon(s):
    t = s.strip()
    if not t or not BACON_RE.match(t):
        return False
    letters = re.sub(r"\s+", "", t)
    if len(letters) < 10 or len(letters) % 5:
        return False
    toks = t.split()
    return all(len(x) == 5 for x in toks) or len(toks) == 1


def bacon_vals(s):
    letters = re.sub(r"\s+", "", s.strip()).lower()
    return [int(letters[i:i + 5].replace("a", "0").replace("b", "1"), 2) for i in range(0, len(letters), 5)]


def bacon_decodes(s):
    """[(label, text)] decodings of an a/b Bacon blob: nibble-hex (16 symbols) first, then 26- and 24-letter alphabets."""
    v = bacon_vals(s)
    out = []
    if v and all(x < 16 for x in v):
        hx = "".join("%x" % x for x in v)
        if len(hx) % 2 == 0:
            try:
                out.append(("baconhex", binascii.unhexlify(hx).decode("utf-8")))
            except Exception:
                pass
        out.append(("baconhexstr", hx))
    if all(x < 26 for x in v):
        t = "".join(_AZ[x] for x in v)
        out.append(("bacon", t)); out.append(("baconup", t.upper()))
    if all(x < 24 for x in v):
        out.append(("bacon24", "".join(_B24[x] for x in v)))
    return out


# ---------------------------------------------------------------- rail fence (day 18)
def rail_idx(n, rails):
    idx = []; r = 0; d = 1
    for _ in range(n):
        idx.append(r)
        if rails > 1:
            if r == 0: d = 1
            elif r == rails - 1: d = -1
            r += d
    return idx


def rail_dec(c, rails):
    """invert the zigzag write-out: ciphertext = rail0 chars, then rail1 chars, ... (standard rail fence)."""
    n = len(c)
    idx = rail_idx(n, rails)
    out = [None] * n; pos = 0
    for rr in range(rails):
        for i in range(n):
            if idx[i] == rr:
                out[i] = c[pos]; pos += 1
    return "".join(out)


RAILS = (3, 2, 4, 5, 6)


def rail_candidates(t):
    """[(label, text)] rail-fence decodes; a decode that names the Game Master is returned alone."""
    out = []
    for r in RAILS:
        if len(t) < r:
            continue
        d = rail_dec(t, r)
        if "game master" in d.lower() or d.lower().startswith("nice work"):
            return [("rail%d" % r, d)]
        out.append(("rail%d" % r, d))
    return out


def atbash(s):
    return s.translate(ATBASH)


def caesar(s, k):
    """shift letters by k (case preserved)."""
    k %= 26
    t = str.maketrans(_AZ + _AZ.upper(), _AZ[k:] + _AZ[:k] + _AZ.upper()[k:] + _AZ.upper()[:k])
    return s.translate(t)


# English letter-trigram model (from local license texts) to rank ambiguous fragment decodings
_TRI, _BI = {}, {}


def _norm(s):
    return re.sub(r"[^a-z]+", " ", s.lower())


def _load_model():
    if _TRI:
        return
    txt = []
    d = "/usr/share/common-licenses"
    for fn in sorted(os.listdir(d)) if os.path.isdir(d) else []:
        p = os.path.join(d, fn)
        if os.path.isfile(p):
            txt.append(open(p, encoding="utf-8", errors="ignore").read())
    t = " " + _norm(" ".join(txt)) + " "
    for i in range(len(t) - 2):
        _TRI[t[i:i + 3]] = _TRI.get(t[i:i + 3], 0) + 1
        _BI[t[i:i + 2]] = _BI.get(t[i:i + 2], 0) + 1


def eng_score(s):
    """mean log P(c3|c1c2) over letter trigrams; higher = more English-like."""
    import math
    _load_model()
    t = " " + _norm(s) + " "
    if len(t.strip()) == 0:
        return -9.0  # no letters at all = garbage, must rank below any real text (was 0.0 = best possible)
    tot, n = 0.0, 0
    for i in range(len(t) - 2):
        tri, bi = t[i:i + 3], t[i:i + 2]
        tot += math.log((_TRI.get(tri, 0) + 0.1) / (_BI.get(bi, 0) + 2.7))
        n += 1
    return tot / max(n, 1)


def rot47(s):
    return "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in s)


def pad(s, n):
    s = s.rstrip("=")
    return s + "=" * (-len(s) % n)


def layers(s):
    """candidate decodings of a text blob (one layer)."""
    t = re.sub(r"^\d+\t", "", s.strip())
    c = re.sub(r"\s+", "", t)
    out = []
    if is_bacon(t):
        return [x for _, x in bacon_decodes(t)]
    if is_morse(t):
        m = morse(t)
        out.append(m.encode()); out.append(m.lower().encode())
        return [x.decode() for x in out]
    rc = rail_candidates(t)
    if len(rc) == 1:  # a rail decode names the Game Master -> that's the layer
        return [rc[0][1]]
    rc_stripped = rail_candidates(t.rstrip())
    if len(rc_stripped) == 1:
        return [rc_stripped[0][1]]
    if re.fullmatch(r"[A-Za-z0-9_\-]+=*", c):
        try: out.append(base64.urlsafe_b64decode(pad(c, 4)))
        except Exception: pass
    try: out.append(base64.b64decode(pad(c, 4), validate=True))
    except Exception: pass
    try: out.append(base64.b32decode(pad(c.upper(), 8)))
    except Exception: pass
    try: out.append(binascii.unhexlify(c))
    except Exception: pass
    out.append(rot47(t).encode())
    out.append(caesar(t, -7).encode())
    out.append(caesar(t, 7).encode())
    out.append(atbash(t).encode())
    out.append(codecs.encode(t, "rot13").encode())
    out.append(t[::-1].encode())
    out.append("\n".join(l[::-1] for l in t.splitlines()).encode())
    for _, x in rc:
        out.append(x.encode())
    res = []
    for o in out:
        u = u16(o)
        if u is not None:
            res.append(u); continue
        try: res.append(o.decode("utf-8"))
        except Exception: pass
    return res


def _pr(b):
    try: s = b.decode("ascii") if isinstance(b, bytes) else b
    except Exception: return None
    return s if s and all(32 <= ord(c) < 127 for c in s) else None


def u16(b):
    """day 19 'Little Things': UTF-16 text (BOM FF FE / FE FF, or BOM-less LE/BE with zero high bytes) -> str, else None."""
    if not isinstance(b, (bytes, bytearray)) or len(b) < 4:
        return None
    try:
        if b[:2] == b"\xff\xfe":
            return b[2:].decode("utf-16-le")
        if b[:2] == b"\xfe\xff":
            return b[2:].decode("utf-16-be")
        if len(b) % 2 == 0:
            if all(b[i] == 0 for i in range(1, len(b), 2)) and all(b[i] != 0 for i in range(0, len(b), 2)):
                return b.decode("utf-16-le")
            if all(b[i] == 0 for i in range(0, len(b), 2)) and all(b[i] != 0 for i in range(1, len(b), 2)):
                return b.decode("utf-16-be")
    except Exception:
        return None
    return None


def line_decode_l(f):
    """decode one mixed-codec fragment; [(codec_label, text)], plausible decodings, best first."""
    f = f.rstrip("\r\n")
    out = []
    def add(lab, x):
        u = u16(x)
        if u is not None:
            lab, x = lab + "16", u
        x = _pr(x)
        if x is not None and x not in [o[1] for o in out]: out.append((lab, x))
    if is_bacon(f):
        for lab, x in bacon_decodes(f):
            add(lab, x)
        return out
    if is_morse(f):
        m = morse(f)
        c = re.sub(r"\s+", "", m)
        if re.fullmatch(r"([0-9A-Fa-f]{2})+", c):
            try: add("morsehex", binascii.unhexlify(c))
            except Exception: pass
        if re.fullmatch(r"[A-Z2-7]+=*", c):
            try: add("morseb32", base64.b32decode(pad(c, 8)))
            except Exception: pass
        if re.fullmatch(r"\d{1,3}( \d{1,3})*", m):
            try: add("morsedec", bytes(int(t) for t in m.split()))
            except Exception: pass
        add("morse", m); add("morselow", m.lower())
        return out
    if f.startswith('"') and f.endswith('"') and "\\u" in f:
        try: add("json", json.loads(f))
        except Exception: pass
    if "&#" in f: add("html", html.unescape(f))
    if re.fullmatch(r"(%[0-9A-Fa-f]{2})+", f): add("url", urllib.parse.unquote(f))
    if re.fullmatch(r"[01]{8}( [01]{8})*", f): add("bin", bytes(int(t, 2) for t in f.split()))
    if re.fullmatch(r"\d{1,3}( \d{1,3})*", f):
        toks = f.split()
        dec = None if any(int(t) > 255 for t in toks) else _pr(bytes(int(t) for t in toks))
        octv = None if re.search(r"[89]", f) else _pr(bytes(int(t, 8) for t in toks if int(t, 8) < 256))
        lead0 = any(len(t) > 1 and t[0] == "0" for t in toks)
        for lab, x in ([("oct", octv), ("dec", dec)] if lead0 else [("dec", dec), ("oct", octv)]):
            if x is not None: add(lab, x)
    if re.fullmatch(r"([0-9a-fA-F]{2})+", f): add("hex", binascii.unhexlify(f))
    if re.fullmatch(r"[A-Z2-7]+=*", f):
        try: add("b32", base64.b32decode(pad(f, 8)))
        except Exception: pass
    if re.fullmatch(r"[A-Za-z0-9_\-]+=*", f):
        try: add("b64u", base64.urlsafe_b64decode(pad(f, 4)))
        except Exception: pass
    if re.fullmatch(r"[A-Za-z0-9+/]+=*", f):
        try: add("b64", base64.b64decode(pad(f, 4)))
        except Exception: pass
    add("r47", rot47(f))
    add("c7", caesar(f, -7))
    add("c7r", caesar(f, 7))
    add("atbash", atbash(f))
    add("rot13", codecs.encode(f, "rot13"))
    add("rev", f[::-1])
    for lab, x in rail_candidates(f):
        add(lab, x)
    return out


def line_decode(f):
    return [x for _, x in line_decode_l(f)]


# per-line-position codec preference learned across a mastery bundle (positions use a fixed codec)
POS_RANK = {}


def _rows(s):
    rows = []
    for l in s.splitlines():
        if not l.strip(): continue
        m = re.match(r"^(\d+)\t(.*)$", l)
        if not m: return None
        rows.append((int(m.group(1)), m.group(2)))
    return sorted(rows)


def learn_positions(blobs):
    """aggregate English score per (line index, codec) over many blobs -> label preference per index."""
    agg = {}
    for raw in blobs:
        s = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
        rows = _rows(s) if re.match(r"^\d+\t", s) else None
        if not rows or len(rows) < 2: continue
        for i, f in rows:
            for lab, x in line_decode_l(f):
                a = agg.setdefault(i, {}).setdefault(lab, [0.0, 0])
                a[0] += eng_score(x); a[1] += 1
    POS_RANK.clear()
    for i, d in agg.items():
        POS_RANK[i] = sorted(d, key=lambda lab: -(d[lab][0] / d[lab][1]))


TEMPLATE = re.compile(r"Game Master: ([a-z]+-[a-z]+-[a-z]+-\d{2})\.?$", re.I)


TEMPLATE_TEXT = "nice work decoding this warmup! to solve, submit this exact answer to the game master: "
SLUG_FULL = re.compile(r"^[a-z]+-[a-z]+-[a-z]+-\d{2}\.?$")
SLUG_PART = re.compile(r"^[a-z\-]*(\d{0,2}\.?)?$")


def solve_template(cands):
    """left-to-right search: the concatenated fragments must stay a prefix of TEMPLATE_TEXT (case-insensitive) and then form
    a slug word-word-word-NN. cands = per-row candidate texts (any order). Returns (slug, message) or None."""
    T = TEMPLATE_TEXT
    states = [("", "")]  # (lowercased accumulated text, original-case text)
    for lc in cands:
        nxt = []; seen = set()
        for low, orig in states:
            for x in lc:
                nl = low + x.lower()
                if len(nl) <= len(T):
                    ok = T.startswith(nl)
                else:
                    ok = nl.startswith(T) and bool(SLUG_PART.match(nl[len(T):]))
                if ok and nl not in seen:
                    seen.add(nl); nxt.append((nl, orig + x))
        states = nxt[:5000]
        if not states:
            return None
    for low, orig in states:
        tail = low[len(T):] if len(low) > len(T) else ""
        if SLUG_FULL.match(tail):
            return tail.rstrip("."), orig
    return None


def solve_mixed(s):
    rows = _rows(s)
    if not rows: return None
    cands = []
    for i, f in rows:
        lc = line_decode_l(f)
        if not lc: return None
        rank = POS_RANK.get(i)
        if rank:  # codec learned for this line position across the bundle
            lc.sort(key=lambda t: (rank.index(t[0]) if t[0] in rank else 99, -eng_score(t[1])))
        else:     # most English-like decoding first (atbash/rot13/reverse all yield letter soup)
            lc.sort(key=lambda t: -eng_score(t[1]))
        cands.append([x for _, x in lc])
    r = solve_template(cands)
    if r:
        return r
    fallback = None
    for combo in itertools.islice(itertools.product(*cands), 4096):
        msg = "".join(combo)
        m = TEMPLATE.search(msg)
        if m and msg.lower().startswith("nice work"): return m.group(1).lower(), msg
        if m and fallback is None: fallback = (m.group(1).lower(), msg)
    return fallback


def solve_blob(raw):
    s = u16(raw)
    if s is None:
        s = raw.decode("utf-8", "replace")
    if re.match(r"^\d+\t", s) and len([l for l in s.splitlines() if l.strip()]) > 1:
        r = solve_mixed(s)
        if r: return r
    frontier = [s]
    for depth in range(10):
        nxt = []
        for x in frontier:
            lines = [l for l in x.splitlines() if l.strip()]
            if lines and "game master" in lines[-1].lower():
                m = SLUG.findall(lines[-1].lower())
                if m: return m[-1], x
            nxt.extend(layers(x))
        frontier = []; seen = set()
        for n in nxt:
            if n and n not in seen and sum(ch.isprintable() or ch in "\r\n\t" for ch in n) > 0.95 * len(n):
                seen.add(n); frontier.append(n)
        frontier.sort(key=lambda n: -eng_score(n))
        frontier = frontier[:64]  # cap: the uncapped search exploded exponentially (day 20)
        if not frontier: break
    return None, s


def main():
    ch = sys.argv[1]
    if ch == "local":
        d = sys.argv[2]
        fns = [fn for fn in sorted(os.listdir(d)) if not fn.endswith(".json")]
        learn_positions([open(os.path.join(d, fn), "rb").read() for fn in fns])
        print("POS_RANK", {k: v[:2] for k, v in sorted(POS_RANK.items())})
        for fn in fns:
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
    if len(files) > 1:
        learn_positions(list(files.values()))
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
