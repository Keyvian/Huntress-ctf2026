"""Forward and inverse of the two ARX block-cipher passes in sha1-hulud's input transform (16 rounds, 128-bit block)."""
import pefile

M = (1 << 64) - 1
_pe = pefile.PE("~/d30/hulud/x/sha1-hulud.exe", fast_load=True)
_img = _pe.get_memory_mapped_image()
_d = lambda rva, n: [int.from_bytes(_img[rva + i * 4:rva + i * 4 + 4], "little") for i in range(n)]


def rol(x, n):
    n &= 63
    return ((x << n) | (x >> (64 - n))) & M if n else x


def mix(x):
    x ^= x >> 29
    x = x * 0xb89294a129ad1091 & M
    x ^= x >> 35
    x = x * 0xf6e2e6bfab39e8f7 & M
    x ^= x >> 26
    return x


def tf(y):
    return (y + (((y * y) & M) | 5)) & M


def tf_inv(z):
    y = 0
    for i in range(64):
        if (tf(y) ^ z) >> i & 1:
            y |= 1 << i
    return y


def unxsr(v, n):      # invert v ^= v >> n
    r = v
    for _ in range(64 // n + 1):
        r = v ^ (r >> n)
    return r & M


def unxsl(v, n):      # invert v ^= v << n
    r = v
    for _ in range(64 // n + 1):
        r = (v ^ (r << n)) & M
    return r


# pass parameters: (rotation-table rva, k-step, per-round step, xorshift amounts (a, b, c, d))
P1 = dict(tab=0x58556 + 7 + 0x2faa3, kstep=0x40714d53b9553253, rstep=0x80e29aa772aa64a6, xs=(10, 21, 14, 33))
P2 = dict(tab=0x58870 + 7 + 0x2f831, kstep=0xb19e19b36281f0b9, rstep=0x633c3366c503e172, xs=(30, 26, 24, 29))


def enc(p, key, s, rc):
    s = list(s)
    T = _d(p["tab"], 32)
    a, b, c, d = p["xs"]
    for r in range(16):
        k = rc
        for j in range(2):
            x = mix(key[j] ^ k)
            y = (s[j] + x) & M if j == 0 else s[j] ^ x
            s[j] = tf(y)
            k = (k + p["kstep"]) & M
        s[0] ^= rol(s[1], T[r * 2])
        s[1] ^= rol(s[0], T[r * 2 + 1])
        u = s[0] ^ (s[0] >> a); u ^= (u << b) & M
        v = s[1] ^ ((s[1] << c) & M); v ^= v >> d
        s[0], s[1] = v, u
        rc = (rc + p["rstep"]) & M
    return s


def dec(p, key, s, rc0):
    s = list(s)
    T = _d(p["tab"], 32)
    a, b, c, d = p["xs"]
    rcs = [(rc0 + i * p["rstep"]) & M for i in range(16)]
    for r in range(15, -1, -1):
        v, u = s[0], s[1]
        u = unxsr(unxsl(u, b), a)
        v = unxsl(unxsr(v, d), c)
        s[0], s[1] = u, v
        s[1] ^= rol(s[0], T[r * 2 + 1])
        s[0] ^= rol(s[1], T[r * 2])
        for j in (1, 0):
            k = (rcs[r] + j * p["kstep"]) & M
            x = mix(key[j] ^ k)
            y = tf_inv(s[j])
            s[j] = (y - x) & M if j == 0 else y ^ x
    return s
