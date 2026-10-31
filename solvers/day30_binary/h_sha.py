"""Check whether the protected compress at 0x1080 is plain SHA-1: IN/OUT captured from the emulator (--cmptest)."""
import struct, sys


def rol(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xffffffff


def rounds(st, w):
    w = list(w)
    for t in range(16, 80):
        w.append(rol(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1))
    a, b, c, d, e = st
    for t in range(80):
        if t < 20: f, k = (b & c) | (~b & d), 0x5a827999
        elif t < 40: f, k = b ^ c ^ d, 0x6ed9eba1
        elif t < 60: f, k = (b & c) | (b & d) | (c & d), 0x8f1bbcdc
        else: f, k = b ^ c ^ d, 0xca62c1d6
        a, b, c, d, e = (rol(a, 5) + (f & 0xffffffff) + e + k + w[t]) & 0xffffffff, a, rol(b, 30), c, d
    return a, b, c, d, e


IN = bytes.fromhex(sys.argv[1])
OUT = bytes.fromhex(sys.argv[2])
st = struct.unpack("<5I", IN[:20])
w = struct.unpack("<16I", IN[0x18:0x58])
print("in state", [hex(x) for x in st])
print("out state", [hex(x) for x in struct.unpack("<5I", OUT[:20])])
print("plain   ", [hex(x) for x in rounds(st, w)])
w2 = struct.unpack(">16I", IN[0x18:0x58])
print("byteswap", [hex(x) for x in rounds(st, w2)])
