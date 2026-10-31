"""Independent re-implementation (Java 64-bit semantics) of the jadx output of the Day-25 time_trial APK
(com.huntress.mobile.d25.v0cd8ca0759e5, case MOB-25-0CD8CA0759) to cross-check dalvik.py before submitting.
Constants are copied from the decompiled Release/VerdictMap/Probe/IntegritySignals/SealCheck/Mix classes of THIS variant."""
M = (1 << 64) - 1


def u(x): return x & M
def s64(x):
    x &= M
    return x - (1 << 64) if x >> 63 else x
def rotl(x, n): x &= M; n %= 64; return ((x << n) | (x >> (64 - n))) & M
def ushr(x, n): return (x & M) >> n
def mul(a, b): return (a * b) & M
def i32(x):
    x &= 0xFFFFFFFF
    return x - (1 << 32) if x >> 31 else x


def s2(i, i2, i3, i4):
    for i5 in range(4096):
        if ((((i5 ^ i3) * i) + i2) & 4095) == i4:
            return i5
    return -1


def s3(i, i2, i3, i4):
    i5 = (i % 11) + 1
    i6 = 12 - i5
    for i7 in range(4096):
        i8 = (i7 ^ i3) & 4095
        if ((((i8 >> i6) | (i8 << i5)) + i2) & 4095) == i4:
            return i7
    return -1


def integrity_statement(j, i):  # ((long) i) ^ j
    return u(u(i) ^ u(j))


def mixIntegrityc6(j):
    j2 = mul(u(j) ^ ushr(j, 40), -3789725828586584737)
    j3 = rotl(j2, 58)
    j4 = j3 ^ ushr(j3, 38)
    return u((j4 ^ ushr(j4, 37)) ^ u(-3967621508881063642) ^ u(-8045006203117217816))


def mixVerdictde(j):
    j2 = mul(u(j) ^ u(-8060719325963200665), 4238217401161455089)
    return u(rotl(j2, 41) ^ u(309271044109046072) ^ u(1947210816068111766))


def scanIntegritya4(j):
    iS2 = s2(2209, 3470, 1681, 1596)
    iS3 = s3(530, 1697, 1105, 1027)
    stmt = u(i32(integrity_statement(u(iS2), iS3)))  # (long)(int) integrityStatement(iS2, iS3)
    a = u(j) ^ u(0 ^ mul(u(iS2), -7915556545013646311) ^ mul(u(iS3), -6709159976589358661))
    b = u(mul(a, -8969817188253259747) + mul(stmt, -8148014131207759489))
    c = u(b ^ u(-8060062790275093425))
    d = u(c - u(8206660402193616883))
    return mul(d, 8133977348377752479), iS2, iS3


def f1(j):
    j2 = mul(u(j) ^ ushr(j, 46), 6294280497722454281)
    j3 = rotl(j2, 48)
    j4 = j3 ^ ushr(j3, 45)
    j5 = mul(rotl(j4, 53), -1048071659502943555)
    j6 = rotl(j5, 20) ^ u(-213712380810883309)
    j7 = j6 ^ ushr(j6, 8)
    j8 = rotl(j7, 8)
    return u(j8 ^ ushr(j8, 14))


def finIntegrity9a(j):
    j2 = mul(j, -8573698049191013563)
    j3 = mul(j2 ^ ushr(j2, 12), -502530058015175083)
    x = u(rotl(j3, 46) - u(6046435911753674793))
    return mul(mul(x, -2864617985427068091), 2750720910232280867)


def token():
    t, a, b = scanIntegritya4(mixIntegrityc6(u(-2221441761908824129)))
    return mixVerdictde(t), a, b


def code():
    t, a, b = token()
    v = finIntegrity9a(f1(t)) ^ u(6827433075968003619)
    return "ANS-" + "".join("0123456789ABCDEF"[(v >> i) & 15] for i in range(60, -1, -4)), a, b, t


if __name__ == "__main__":
    c, a, b, t = code()
    print("s2", a, "s3", b, "token %016x" % t, "proof", "%x" % t, "code", c)
