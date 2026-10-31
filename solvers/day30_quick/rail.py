"""Rail-fence (zigzag) decoder. usage: rail.py <file> [rails...]"""
import sys


def rail_idx(n, rails):
    idx = []; r = 0; d = 1
    for i in range(n):
        idx.append(r)
        if rails > 1:
            if r == 0: d = 1
            elif r == rails - 1: d = -1
            r += d
    return idx


def rail_dec(c, rails, offset=0):
    n = len(c)
    idx = rail_idx(n + offset, rails)[offset:]
    out = [None] * n; pos = 0
    for rr in range(rails):
        for i in range(n):
            if idx[i] == rr:
                out[i] = c[pos]; pos += 1
    return "".join(out)


def rail_enc(p, rails):
    idx = rail_idx(len(p), rails)
    return "".join(p[i] for rr in range(rails) for i in range(len(p)) if idx[i] == rr)


if __name__ == "__main__":
    s = open(sys.argv[1], "rb").read().decode("latin1")
    rs = [int(x) for x in sys.argv[2:]] or [2, 3, 4]
    for r in rs:
        print(r, repr(rail_dec(s, r)))
        if s != s.rstrip("\r\n"):
            print(r, "stripped", repr(rail_dec(s.rstrip("\r\n"), r)))
