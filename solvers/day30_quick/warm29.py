"""Day-29 warmup 'Rotten Base' ("Sixty-four invited thirteen over. Things got scrambled." = Base64 text put through ROT13)
solver, all modes. warm29 = warm28 (imported; chains warm24 <- warm25 <- warm26 <- warm28) + a rot13->base64 codec installed by
monkeypatching warm24.layers / line_decode_l (main() and warm26.solve_mixed resolve them through the warm24 module globals).

Rotten Base: the Base64 text was ROT13'd (letters only; digits, + / = untouched), so base64.b64decode(rot13(t)) gives the text.
The single / time_trial whole blob already decoded through the layer soup; the mastery NN\t rows (row 29 = this codec, e.g.
`oP03At==` -> `bC03Ng==` -> `l-76`) need a strong row decoder so warm26.solve_mixed never drops into the slow fallback.
usage: warm29.py <challenge> [op=start|retry|practice] [dry]     (env SAVE=<dir> saves start.json+artifact)
       warm29.py local <dir>"""
import sys, os, re, base64, binascii, codecs
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import warm28  # noqa: F401  (installs revhex + everything before it into warm24)
import warm26
import warm24
from warm24 import _pr

B64ONLY = re.compile(r"^[A-Za-z0-9+/_\-]+=*$")


def rot13b64(t):
    h = re.sub(r"\s+", "", t)
    if len(h) < 2 or not B64ONLY.match(h):
        return None
    r = codecs.decode(h, "rot13")
    r = r.replace("-", "+").replace("_", "/")
    r += "=" * (-len(r.rstrip("=")) % 4) if "=" not in r else ""
    try:
        b = base64.b64decode(r, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not s or sum(c.isprintable() or c in "\r\n\t" for c in s) < len(s):
        return None
    return s


_orig_layers28 = warm24.layers
_orig_line_decode_l28 = warm24.line_decode_l


def layers(s):
    t = re.sub(r"^\d+\t", "", s.strip())
    r = rot13b64(t)
    out = _orig_layers28(s)
    if r is not None and r not in out:
        return [r] + out
    return out


def line_decode_l(f):
    out = _orig_line_decode_l28(f)
    r = rot13b64(f.rstrip("\r\n"))
    if r is not None:
        p = _pr(r)
        if p is not None and p not in [o[1] for o in out]:
            out = out + [("r13b64", p)]
    return out


warm26.STRONG_LABELS.add("r13b64")
warm24.layers = layers
warm24.line_decode_l = line_decode_l

if __name__ == "__main__":
    warm24.main()
