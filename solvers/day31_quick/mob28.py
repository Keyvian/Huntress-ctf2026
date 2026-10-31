"""Day-28 mobile 'Protocol Reconstruction' ("Reconstruct the app-to-backend protocol and preserve nonce and ordering
semantics."): mob26 + NEW puzzle v1 codec "packet". Single-solve variant:
  {"schema":"huntress.mobile.puzzle.v1","day":28,"codec":"packet","data":"484114414e532d36...4311"}
data = hex of one binary frame: magic "HA" | u8 payload length | payload (the ANS- code) | u8 checksum = XOR of every
preceding frame byte. decode_packet() parses a stream of such frames strictly (magic, length, checksum), and if several
frames are present orders them by an explicit sequence/nonce prefix when one exists, otherwise keeps wire order.
Installed by monkeypatching mob19.dec (resolved through the module global by every puzzle_answer in the mob19..mob26
chain), then mob26's __main__ runs unchanged.
usage: mob28.py <challenge> [--submit] [--retry|--practice] [--save dir] | mob28.py --local file...
       mob28.py --packet <hex>      (just decode one data string, with diagnostics)"""
import sys, os, re, base64, runpy
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mob19
from mob19 import ANS

_orig_dec = mob19.dec


def _raw(data):
    t = re.sub(r"\s+", "", data or "")
    if re.fullmatch(r"(?:[0-9A-Fa-f]{2})+", t):
        return bytes.fromhex(t)
    return base64.b64decode(t + "=" * (-len(t) % 4))


def frames(b):
    """Strict parse: [(magic, payload, checksum_ok)] or raise ValueError."""
    out = []
    i = 0
    while i < len(b):
        if len(b) - i < 4:
            raise ValueError("trailing %d bytes at %d" % (len(b) - i, i))
        magic = b[i:i + 2]
        n = b[i + 2]
        end = i + 3 + n
        if end + 1 > len(b):
            raise ValueError("frame at %d length %d overruns" % (i, n))
        x = 0
        for c in b[i:end]:
            x ^= c
        out.append((magic, b[i + 3:end], x == b[end]))
        i = end + 1
    return out


def decode_packet(data, p=None, verbose=False):
    b = _raw(data)
    fr = frames(b)
    if verbose:
        print("  packet frames", [(m, pl, ok) for m, pl, ok in fr])
    bad = [k for k, (_, _, ok) in enumerate(fr) if not ok]
    if bad:
        print("  packet: checksum mismatch in frames", bad)
    good = [pl for _, pl, ok in fr if ok] or [pl for _, pl, _ in fr]
    for pl in good:  # one frame carrying the whole code
        s = pl.decode("latin1")
        if ANS.fullmatch(s.strip()):
            return s.strip()
    seq = []  # several frames: explicit u8 sequence number prefix, else wire order
    if all(len(pl) >= 1 for pl in good) and sorted(pl[0] for pl in good) == list(range(len(good))):
        seq.append(b"".join(pl[1:] for pl in sorted(good, key=lambda pl: pl[0])))
    seq.append(b"".join(good))
    for s in seq:
        t = s.decode("latin1").strip()
        if ANS.fullmatch(t):
            return t
    return seq[-1].decode("latin1")


def dec(codec, data, p):
    if (codec or "").lower() in ("packet", "frame", "framed", "binary_protocol"):
        return decode_packet(data, p, verbose=True)
    return _orig_dec(codec, data, p)


mob19.dec = dec

if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--packet":
        print(decode_packet(sys.argv[2], verbose=True)); sys.exit(0)
    sys.argv[0] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mob26.py")
    runpy.run_path(sys.argv[0], run_name="__main__")
