"""Day-25 warmup 'You Have a Point' ("Every character has a point. A code point, anyway." = Unicode code-point notation
`U+004E U+0069 ...`) solver, all modes. warm25 = warm24 (imported; it has a __main__ guard so importing is safe) + a
code-point codec installed by monkeypatching warm24.layers / line_decode_l / solve_blob (main() resolves them through the
module globals, so the patched versions are used everywhere, including learn_positions and the Day-21..24 fallbacks).

cp_candidates() accepts whitespace/comma separated tokens in any ONE of these spellings (whole blob or one NN\t row):
  U+004E / u+4e        \\u004E / \\U0001F600 / \\x4E      &#x4E; / &#78;      0x4E      decimal 78 (any value < 0x110000)
and returns the chr()-joined text. Multi-byte code points are kept as-is (chr()), so emoji / non-ASCII are fine.
usage: warm25.py <challenge> [op=start|retry|practice] [dry]     (env SAVE=<dir> saves start.json+artifact)
       warm25.py local <dir>"""
import sys, os, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import warm24
from warm24 import inflate, u16, _pr

CP_FORMS = [
    ("cpU", re.compile(r"^[Uu]\+([0-9A-Fa-f]{2,6})$")),
    ("cpbs", re.compile(r"^\\[uU]([0-9A-Fa-f]{4,8})$")),
    ("cpx", re.compile(r"^\\x([0-9A-Fa-f]{2})$")),
    ("cphtmlx", re.compile(r"^&#[xX]([0-9A-Fa-f]{1,6});$")),
    ("cphtml", re.compile(r"^&#(\d{1,7});$")),
    ("cp0x", re.compile(r"^0[xX]([0-9A-Fa-f]{1,6})$")),
    ("cpdec", re.compile(r"^(\d{1,7})$")),
]
SPLIT = re.compile(r"[\s,;]+")
GLUED = re.compile(r"(?:[Uu]\+[0-9A-Fa-f]{4,6})+$|(?:\\[uU][0-9A-Fa-f]{4})+$|(?:&#[xX]?[0-9A-Fa-f]{1,7};)+$")


def _toks(t):
    t = t.strip()
    if not t:
        return []
    toks = [x for x in SPLIT.split(t) if x]
    if len(toks) == 1 and GLUED.match(toks[0]):  # glued form without separators: U+004EU+0069… or Ni… or &#x4E;&#x69;
        toks = re.findall(r"[Uu]\+[0-9A-Fa-f]{4,6}|\\[uU][0-9A-Fa-f]{4}|&#[xX]?[0-9A-Fa-f]{1,7};", toks[0])
    return toks


def cp_candidates(t):
    """[(label, text)] code-point decodings of a text blob; every token must match the same spelling."""
    toks = _toks(t)
    if len(toks) < 2 and not (len(toks) == 1 and CP_FORMS[0][1].match(toks[0])):
        return []
    out = []
    for lab, rx in CP_FORMS:
        vals = []
        for x in toks:
            m = rx.match(x)
            if not m:
                vals = None; break
            v = int(m.group(1), 10 if lab in ("cpdec", "cphtml") else 16)
            if v >= 0x110000 or 0xD800 <= v <= 0xDFFF:
                vals = None; break
            vals.append(v)
        if vals:
            s = "".join(chr(v) for v in vals)
            if s and sum(ch.isprintable() or ch in "\r\n\t" for ch in s) > 0.9 * len(s):
                out.append((lab, s))
    return out


_orig_layers24 = warm24.layers
_orig_line_decode_l24 = warm24.line_decode_l
_orig_solve_blob24 = warm24.solve_blob


def layers(s):
    t = re.sub(r"^\d+\t", "", s.strip())
    res = [x for lab, x in cp_candidates(t) if lab != "cpdec"]
    if res and re.match(r"^\s*(?:[Uu]\+|\\[uUx]|&#)", t):
        return res  # an explicit code-point notation is unambiguous: do not fan out into the rot/atbash/base64 soup
    res += [x for lab, x in cp_candidates(t) if lab == "cpdec"]
    return res + _orig_layers24(s)


def line_decode_l(f):
    out = _orig_line_decode_l24(f)
    ff = f.rstrip("\r\n")
    extra = []
    for lab, x in cp_candidates(ff):
        if lab == "cpdec":
            continue  # plain decimal rows are already handled by warm14's "dec" codec (bytes) — keep its label/ranking
        p = _pr(x) if all(ord(c) < 128 for c in x) else x
        if p is not None and p not in [o[1] for o in out] and p not in [o[1] for o in extra]:
            extra.append((lab, p))
    if extra and re.match(r"^\s*(?:[Uu]\+|\\[uUx]|&#)", ff):
        return extra + out  # explicit code-point row: its decode goes first
    return out + extra


def solve_blob(raw):
    """Code-point-first: if the whole blob is one code-point stream, decode it and hand the text to the Day-24 solver (which
    also handles a non-code-point blob or a stream whose payload is itself another codec)."""
    r = raw
    for _ in range(4):
        d = inflate(r)
        if d is None:
            break
        r = d
    s = u16(r)
    if s is None:
        s = r.decode("utf-8", "replace")
    cands = [x for lab, x in cp_candidates(s) if lab != "cpdec"]
    for c in cands:
        slug, msg = _orig_solve_blob24(c.encode("utf-8"))
        if slug:
            return slug, msg
    return _orig_solve_blob24(raw)


warm24.layers = layers
warm24.line_decode_l = line_decode_l
warm24.solve_blob = solve_blob

if __name__ == "__main__":
    warm24.main()
