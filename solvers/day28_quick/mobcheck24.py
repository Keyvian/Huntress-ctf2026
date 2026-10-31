"""Independent re-implementation (Java 64-bit semantics in Python) of the Day-24 time_trial variant's Release.code(), used only
to cross-check dalvik.py's interpreter result for build 3d2feb28e097 / package v4000d435437f. Constants transcribed from jadx."""
M = (1 << 64) - 1


def s64(x):
    x &= M
    return x - (1 << 64) if x >> 63 else x


def ushr(x, n):
    return (x & M) >> n


def shl(x, n):
    return (x << n) & M


def mul(a, b):
    return (a * b) & M


def add(a, b):
    return (a + b) & M


def s1(i, i2, i3, i4):
    for i5 in range(4096):
        if ((((i5 * i) + i2) ^ i3) & 4095) == i4:
            return i5
    return -1


def s2(i, i2, i3, i4):
    for i5 in range(4096):
        if (((((i5 ^ i3) * i) + i2)) & 4095) == i4:
            return i5
    return -1


def mixBoard95(j):
    j2 = mul(j, 6209822824361050893)
    j3 = j2 ^ ushr(j2, 43)
    return add(add(shl(j3, 25) | ushr(j3, 39), -6746275197296197727), 5425963326242299918)


def emulatorScore(a, b, c):
    s = a + b + c
    return int(abs(s) % 4) * (1 if s >= 0 else -1)  # Java truncating remainder


def scanAlibi87(j):
    iS2 = s2(2197, 3637, 2221, 1648)
    iS3 = s2(303, 2185, 3023, 1395)
    iS1 = s1(3951, 230, 2614, 620)
    acc = (0 ^ mul(iS2 & M, -1297437035307179051 & M)) ^ mul(iS3 & M, 8183847891570595153) ^ mul(iS1 & M, -1322936570625680951 & M)
    v = mul(j ^ acc, 4983124125084213197)
    v = add(v, mul(emulatorScore(iS2, iS3, iS1) & M, 995189594965362989))
    v = mul(v ^ (-2698974941407860910 & M), 3933657326363537435)
    return v ^ (-906784454926522698 & M)


def mixSensor4b(j):
    j2 = mul(add(j, 4001714510183354212), -7274959280769029813 & M)
    j3 = j2 ^ ushr(j2, 26)
    j4 = mul(shl(j3, 37) | ushr(j3, 27), 5396880243912846597) ^ 8717838452729586792
    return (shl(j4, 23) | ushr(j4, 41)) & M


def f1(j):
    j2 = add(j ^ ushr(j, 47), 8057753049695711018)
    j3 = add((j2 ^ ushr(j2, 26)) ^ 8036043438537395742, 5129822894954618742) ^ (-5147528772284511864 & M)
    j4 = shl(j3, 30) | ushr(j3, 34)
    return mul(shl(j4, 10) | ushr(j4, 54), 4083034511316523911)


def finEmud6(j):
    j2 = mul(j ^ ushr(j, 8), -7681852081475084355 & M)
    j3 = shl(j2, 44) | ushr(j2, 20)
    j4 = mul(mul(j3 ^ ushr(j3, 25), 3517100198993776909), -821602216634901957 & M)
    j5 = mul(j4 ^ ushr(j4, 15), 4333057866445559187) ^ 945414129063759714
    return j5 ^ ushr(j5, 14)


def code():
    tok = mixSensor4b(scanAlibi87(mixBoard95(994846963492763122)))
    v = finEmud6(f1(tok)) ^ 302887074085206682
    out = "ANS-"
    for i in range(60, -1, -4):
        out += "0123456789ABCDEF"[(v >> i) & 15]
    return out


if __name__ == "__main__":
    print(code())
