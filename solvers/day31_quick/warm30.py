"""Day-30 warmup 'Percent Percent' ("That address bar problem? It happened twice." = double URL/percent encoding) solver, all
modes. warm30 = warm29 (imported; chains warm24 <- warm25 <- warm26 <- warm28 <- warm29) + a double-percent codec installed by
monkeypatching warm24.layers / line_decode_l (main() and warm26.solve_mixed resolve them through the warm24 module globals).

Double percent: every byte is %XX, and the '%' of that result was encoded again (`%25%36%33` -> `%63` -> `c`), so the blob is
unquote(unquote(t)). A once-decoded row is still `%XX` text and can never be right, so the plain "url" candidate is dropped when
this codec matches.
usage: warm30.py <challenge> [op=start|retry|practice] [dry]     (env SAVE=<dir> saves start.json+artifact)
       warm30.py local <dir>"""
import sys, os, re, urllib.parse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import warm29  # noqa: F401  (installs rot13b64 + everything before it into warm24)
import warm26
import warm24
from warm24 import _pr


def durl(t):
    h = re.sub(r"\s+", "", t)
    if "%25" not in h or not re.fullmatch(r"(?:[^%]|%[0-9A-Fa-f]{2})+", h):
        return None
    try:
        s = urllib.parse.unquote(urllib.parse.unquote(h, errors="strict"), errors="strict")
    except UnicodeDecodeError:
        return None
    if not s or re.search(r"%[0-9A-Fa-f]{2}", s) or sum(c.isprintable() or c in "\r\n\t" for c in s) < len(s):
        return None
    return s


_orig_layers29 = warm24.layers
_orig_line_decode_l29 = warm24.line_decode_l


def layers(s):
    t = re.sub(r"^\d+\t", "", s.strip())
    r = durl(t)
    if r is not None:
        return [r]
    return _orig_layers29(s)


def line_decode_l(f):
    r = durl(f.rstrip("\r\n"))
    if r is not None:
        p = _pr(r)
        if p is not None:
            return [("durl", p)]
    return _orig_line_decode_l29(f)


warm26.STRONG_LABELS.add("durl")
warm24.layers = layers
warm24.line_decode_l = line_decode_l

if __name__ == "__main__":
    warm24.main()
