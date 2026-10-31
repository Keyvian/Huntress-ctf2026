"""SHA-1 round function (no feed-forward) and the sample's three protected variants. Each protected routine changes one
small detail of the primitive:
  0x1080  plain SHA-1
  0x10840 schedule tap t-9 instead of t-8
  0x1dfc0 Ch with c and d swapped in rounds 0..19
  0x2b840 b rotated by 2 instead of 30, and Ch kept through round 20"""


def rol(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xffffffff


def rounds(st, w, tap=8, rotl=1, rotb=30, chswap=False, chend=20):
    w = list(w)
    for t in range(16, 80):
        w.append(rol(w[t - 3] ^ w[t - tap] ^ w[t - 14] ^ w[t - 16], rotl))
    a, b, c, d, e = st
    for t in range(80):
        if t < chend:
            f = ((b & d) | (~b & c)) if chswap else ((b & c) | (~b & d))
        elif t < 40:
            f = b ^ c ^ d
        elif t < 60:
            f = (b & c) | (b & d) | (c & d)
        else:
            f = b ^ c ^ d
        k = 0x5a827999 if t < 20 else 0x6ed9eba1 if t < 40 else 0x8f1bbcdc if t < 60 else 0xca62c1d6
        a, b, c, d, e = (rol(a, 5) + (f & 0xffffffff) + e + k + w[t]) & 0xffffffff, a, rol(b, rotb), c, d
    return a, b, c, d, e


VARIANT = {0x1080: dict(), 0x10840: dict(tap=9), 0x1dfc0: dict(chswap=True), 0x2b840: dict(rotb=2, chend=21)}


def compress(fn, st, w):
    return rounds(st, w, **VARIANT[fn])


def rev_rounds(out, w, tap=8, rotl=1, rotb=30, chswap=False, chend=20):
    """Invert the 80 rounds: recover the input state from the output state and the 16 message words."""
    w = list(w)
    for t in range(16, 80):
        w.append(rol(w[t - 3] ^ w[t - tap] ^ w[t - 14] ^ w[t - 16], rotl))
    a, b, c, d, e = out
    for t in range(79, -1, -1):
        a0, b0, c0, d0 = b, rol(c, 32 - rotb), d, e
        if t < chend:
            f = ((b0 & d0) | (~b0 & c0)) if chswap else ((b0 & c0) | (~b0 & d0))
        elif t < 40:
            f = b0 ^ c0 ^ d0
        elif t < 60:
            f = (b0 & c0) | (b0 & d0) | (c0 & d0)
        else:
            f = b0 ^ c0 ^ d0
        k = 0x5a827999 if t < 20 else 0x6ed9eba1 if t < 40 else 0x8f1bbcdc if t < 60 else 0xca62c1d6
        e0 = (a - rol(a0, 5) - (f & 0xffffffff) - k - w[t]) & 0xffffffff
        a, b, c, d, e = a0, b0, c0, d0, e0
    return a, b, c, d, e
