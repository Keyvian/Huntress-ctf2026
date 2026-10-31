"""Day-31 warmup 'One More Thing' ("Thirty-two, a little pressure, then sixty-four. Unpack that thought." = base32 -> gzip -> base64)
solver, all modes. warm31 = warm30 (imported; chains warm24 <- warm25 <- warm26 <- warm28 <- warm29 <- warm30) + a strict codec
installed by monkeypatching warm24.layers / line_decode_l (main() and warm26.solve_mixed resolve them through the warm24 module globals).

Decode order: base64 -> gunzip -> base32. Single/time_trial blob = the whole sentence; mastery row 31 = one fragment.
usage: warm31.py <challenge> [op=start|retry|practice] [dry]     (env SAVE=<dir> saves start.json+artifact)
       warm31.py local <dir>"""
import sys, os, re, gzip, base64, binascii
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import warm30  # noqa: F401  (installs durl + everything before it into warm24)
import warm26
import warm24
from warm24 import _pr


def gz32(t):
    h = re.sub(r"\s+", "", re.sub(r"^\d+\t", "", t.strip()))
    if not h.startswith("H4sI"):
        return None
    try:
        s = base64.b32decode(gzip.decompress(base64.b64decode(h, validate=True))).decode("utf-8")
    except (ValueError, OSError, EOFError, binascii.Error, UnicodeDecodeError):
        return None
    if not s or sum(c.isprintable() or c in "\r\n\t" for c in s) < len(s):
        return None
    return s


_orig_layers30 = warm24.layers
_orig_line_decode_l30 = warm24.line_decode_l


def layers(s):
    r = gz32(s)
    if r is not None:
        return [r]
    return _orig_layers30(s)


def line_decode_l(f):
    r = gz32(f.rstrip("\r\n"))
    if r is not None:
        p = _pr(r)
        if p is not None:
            return [("gz32", p)]
    return _orig_line_decode_l30(f)


warm26.STRONG_LABELS.add("gz32")
warm24.layers = layers
warm24.line_decode_l = line_decode_l

if __name__ == "__main__":
    warm24.main()
