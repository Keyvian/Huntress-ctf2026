"""Day-29 mobile 'White Box Key Recovery' ("Recover an equivalent key operation from challenge-owned table
transformations"): mob28 + NEW puzzle v1 codec "table". Single-solve variant:
  {"schema":"huntress.mobile.puzzle.v1","day":29,"codec":"table","data":"6a7a825f767a6c82...","key":41}
The dex only declares CODEC="table" / CONTROL="white_box_table" (no encoder ships), so the operation is recovered from the
data itself: data[i] = (plain[i] + key + 3*i) mod 256  ->  plain[i] = (data[i] - key - 3*i) mod 256  (every one of the
20 bytes lands on ANS-<16 HEX>). decode_table() also tries the other plausible table families (step 0..255, add/sub/xor with
the per-index key key+step*i) and only accepts a candidate that matches the ANS- pattern, preferring the observed step 3;
it prints every alternative that also matches so an ambiguity is visible. An explicit table/sbox list in the puzzle, if a
variant ever ships one, is inverted first.
Installed by monkeypatching mob19.dec, then mob28 -> mob26's __main__ runs unchanged.
usage: mob29.py <challenge> [--submit] [--retry|--practice] [--save dir] | mob29.py --local file...
       mob29.py --table <hex> <key>      (just decode one data string, with diagnostics)"""
import sys, os, re, base64, runpy
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mob19
import mob28  # noqa: F401  (installs the Day-28 packet codec into mob19.dec)
from mob19 import ANS

_orig_dec = mob19.dec


def _raw(data):
    t = re.sub(r"\s+", "", data or "")
    if re.fullmatch(r"(?:[0-9A-Fa-f]{2})+", t):
        return bytes.fromhex(t)
    return base64.b64decode(t + "=" * (-len(t) % 4))


def _key(k):
    if isinstance(k, int):
        return k & 0xff
    s = str(k).strip()
    if re.fullmatch(r"0x[0-9a-fA-F]+", s):
        return int(s, 16) & 0xff
    return int(s) & 0xff


def candidates(b, key, p=None):
    out = []
    tbl = None
    for name in ("table", "sbox", "box", "lut"):
        if p and isinstance(p.get(name), list) and len(p.get(name)) == 256:
            tbl = p[name]
    if tbl:
        inv = {v & 0xff: i for i, v in enumerate(tbl)}
        for kind, f in (("sbox", lambda c, i: inv.get(c)), ("sbox-k", lambda c, i: inv.get((c - key - 3 * i) & 0xff)),
                        ("k-sbox", lambda c, i: (inv.get(c, 0) - key - 3 * i) & 0xff)):
            try:
                out.append((kind, bytes(f(c, i) for i, c in enumerate(b)).decode("latin1")))
            except Exception:
                pass
    steps = [3] + [s for s in range(256) if s != 3]
    for s in steps:
        out.append(("sub%d" % s, bytes((c - key - s * i) & 0xff for i, c in enumerate(b)).decode("latin1")))
        out.append(("add%d" % s, bytes((c + key + s * i) & 0xff for i, c in enumerate(b)).decode("latin1")))
        out.append(("xor%d" % s, bytes(c ^ ((key + s * i) & 0xff) for i, c in enumerate(b)).decode("latin1")))
    return out


def decode_table(data, p=None, verbose=False):
    key = _key((p or {}).get("key", 0))
    b = _raw(data)
    good = [(k, s) for k, s in candidates(b, key, p) if ANS.fullmatch(s)]
    if verbose or len({s for _, s in good}) != 1:
        print("  table key %d len %d matches %s" % (key, len(b), good[:6]))
    if good:
        return good[0][1]
    return bytes((c - key - 3 * i) & 0xff for i, c in enumerate(b)).decode("latin1")


def dec(codec, data, p):
    if (codec or "").lower() in ("table", "white_box_table", "whitebox", "white_box", "lut", "sbox"):
        return decode_table(data, p, verbose=True)
    return _orig_dec(codec, data, p)


mob19.dec = dec

if __name__ == "__main__":
    if len(sys.argv) > 3 and sys.argv[1] == "--table":
        print(decode_table(sys.argv[2], {"key": sys.argv[3]}, verbose=True)); sys.exit(0)
    sys.argv[0] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mob26.py")
    runpy.run_path(sys.argv[0], run_name="__main__")
