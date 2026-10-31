"""Day-28 warmup 'Back in Sixteen' ("Our sixteen-fingered friend is walking backwards." = hex string written backwards) solver,
all modes. warm28 = warm26 (imported; chains warm24 <- warm25 <- warm26) + a reversed-hex codec installed by monkeypatching
warm24.layers / line_decode_l (main() and warm26.solve_mixed resolve them through the warm24 module globals).

Reversed hex: the whole hex text is reversed character-wise, so bytes.fromhex(t[::-1]) gives the text back. The single /
time_trial blob already decoded through the Day-24 layer soup; the mastery NN\t rows (row 28 = reversed hex) did not, and an
undecodable row sent warm26.solve_mixed into the very slow Day-24 fallback.
usage: warm28.py <challenge> [op=start|retry|practice] [dry]     (env SAVE=<dir> saves start.json+artifact)
       warm28.py local <dir>"""
import sys, os, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import warm26
import warm24
from warm24 import _pr

HEXONLY = re.compile(r"^[0-9A-Fa-f\s]+$")


def revhex(t):
    h = re.sub(r"\s+", "", t)
    if len(h) < 2 or len(h) % 2 or not HEXONLY.match(h):
        return None
    try:
        b = bytes.fromhex(h[::-1])
    except ValueError:
        return None
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not s or sum(c.isprintable() or c in "\r\n\t" for c in s) < len(s):
        return None
    return s


_orig_layers26 = warm24.layers
_orig_line_decode_l26 = warm24.line_decode_l


def layers(s):
    t = re.sub(r"^\d+\t", "", s.strip())
    r = revhex(t)
    out = _orig_layers26(s)
    if r is not None and r not in out:
        return [r] + out
    return out


def line_decode_l(f):
    out = _orig_line_decode_l26(f)
    r = revhex(f.rstrip("\r\n"))
    if r is not None:
        p = _pr(r)
        if p is not None and p not in [o[1] for o in out]:
            out = out + [("revhex", p)]
    return out


warm26.STRONG_LABELS.add("revhex")
warm24.layers = layers
warm24.line_decode_l = line_decode_l

if __name__ == "__main__":
    warm24.main()
