"""Day-30 mobile 'Layered Protections' ("Unwind obfuscation, native indirection, runtime decryption, and integrity checks"):
mob29 + NEW puzzle v1 codec "layered". Single-solve variant:
  {"schema":"huntress.mobile.puzzle.v1","day":30,"codec":"layered","data":"TU49OyInJlUlJSQkKilcKDFOUF4=","key":12}
The dex only declares CODEC="layered" / CONTROL="layered_protections" (no encoder ships), so the operation was recovered from the
data: plain = reversed(base64(data)[i] ^ ((key + i) & 255)). A search over step 0..255 x {xor,add,sub} x {reverse before/after}
gave exactly one ANS-<16 HEX> string. decode_layered() keeps that search and prints every alternative so an ambiguity shows.
Installed by monkeypatching mob19.dec, then mob29 -> mob26's __main__ runs unchanged.
usage: mob30.py <challenge> [--submit] [--retry|--practice] [--save dir] | mob30.py --local file...
       mob30.py --layered <data> <key>      (just decode one data string, with diagnostics)"""
import sys, os, runpy
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mob19
import mob29
from mob19 import ANS

_orig_dec = mob19.dec


def candidates(b, key):
    out = []
    n = len(b)
    r = b[::-1]
    steps = [1] + [s for s in range(256) if s != 1]
    for s in steps:
        for lab, src in (("", b), ("rev>", r)):
            for op, f in (("xor", lambda c, i: c ^ ((key + s * i) & 255)), ("sub", lambda c, i: (c - key - s * i) & 255),
                          ("add", lambda c, i: (c + key + s * i) & 255)):
                v = bytes(f(c, i) for i, c in enumerate(src)).decode("latin1")
                out.append(("%s%s%d>rev" % (lab, op, s), v[::-1]))
                out.append(("%s%s%d" % (lab, op, s), v))
    return out


def decode_layered(data, p=None, verbose=False):
    key = mob29._key((p or {}).get("key", 0))
    b = mob29._raw(data)
    good = [(k, s) for k, s in candidates(b, key) if ANS.fullmatch(s)]
    if verbose or len({s for _, s in good}) != 1:
        print("  layered key %d len %d matches %s" % (key, len(b), good[:6]))
    if good:
        return good[0][1]
    return bytes(c ^ ((key + i) & 255) for i, c in enumerate(b)).decode("latin1")[::-1]


def dec(codec, data, p):
    if (codec or "").lower() in ("layered", "layered_protections"):
        return decode_layered(data, p, verbose=True)
    return _orig_dec(codec, data, p)


mob19.dec = dec

if __name__ == "__main__":
    if len(sys.argv) > 3 and sys.argv[1] == "--layered":
        print(decode_layered(sys.argv[2], {"key": sys.argv[3]}, verbose=True)); sys.exit(0)
    sys.argv[0] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mob26.py")
    runpy.run_path(sys.argv[0], run_name="__main__")
