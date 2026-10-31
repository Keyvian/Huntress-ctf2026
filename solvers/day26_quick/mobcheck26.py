"""Independent cross-check for the Day-26 mobile time_trial variant (package com.huntress.mobile.d26.vaa3cd5de3f13, case
MOB-26-AA3CD5DE3F): a hand re-implementation, with Java long/int semantics, of the jadx output of base.apk/classes.dex.
Release.code = Core.finFeature53(Mix.f1(token())) ^ K;  token = Util.mergeFeature41(Guard.scanBase21(Core.mixBase2f(seed)));
mergeFeature41 reads the 16 bytes of assets/huntress_feature.bin from the feature split (two big-endian u64).
usage: mobcheck26.py <split_decision.apks>   (prints the ANS code; compare with dalvik.py / mob26.py)"""
import sys, io, zipfile

M = (1 << 64) - 1


def u(x):
    return x & M


def ushr(x, n):
    return (x & M) >> n


def rotl(x, n):
    x &= M
    return ((x << n) | (x >> (64 - n))) & M


def probe_s1(i, i2, i3, i4):
    for i5 in range(4096):
        if ((((i5 * i) + i2) ^ i3) & 4095) == i4:
            return i5
    return -1


def probe_s2(i, i2, i3, i4):
    for i5 in range(4096):
        if (((((i5 ^ i3) * i) + i2)) & 4095) == i4:
            return i5
    return -1


def mixBase2f(j):
    j2 = u((j ^ 5794809525850978595) * (-7725049869380990677))
    j3 = j2 ^ ushr(j2, 21)
    return u(j3 ^ ushr(j3, 35))


def splitIndex(a, b):
    return ((a << 4) | b) & 0xFFFFFFFF


def scanBase21(j):
    iS2 = probe_s2(2505, 2928, 3412, 589)
    iS1 = probe_s1(1153, 2766, 3677, 699)
    inner = u((0 ^ u(iS2 * (-7491752324663132103))) ^ u(iS1 * (-3354189015783674173)))
    r = u((j ^ inner) * 9010135782064041793)
    r = u(r + u(splitIndex(iS2, iS1) * 8968887995440588738))
    r = u(r * 8434054145922020495)
    r = u(r ^ u(-4986881201402252921))
    return u(r ^ 2171583740236784838)


def mergeFeature41(j, feat):
    j2 = int.from_bytes(feat[:8], "big")
    j3 = int.from_bytes(feat[8:16], "big")
    j4 = u(j ^ j2)
    j5 = u(u(rotl(j4, 64 - 9) * 8700896853562709015) + j3) ^ 278926787080523225
    return u(rotl(j5, 32) * u(-1593104003058557809))


def f1(j):
    j2 = u(j * u(-1958641036108764657))
    j3 = u(u((j2 ^ ushr(j2, 46)) ^ u(-4314160858224231251)) - 176461582433353968)
    j4 = rotl(j3, 44)
    return u(u(u(rotl(j4, 56) - 4678611288083198865) * u(-1799692469507981683)) * 5699832775629049115)


def finFeature53(j):
    j2 = u(u(u(u(j * 3055877399817786981) - 1170465248488309870) ^ 4901306534401529205) - 6460775826521806748) ^ u(-8326128301722816390)
    j3 = rotl(j2, 61)
    return u(j3 ^ ushr(j3, 25))


def code(feat):
    tok = mergeFeature41(scanBase21(mixBase2f(u(-3130641873769835200))), feat)
    v = u(finFeature53(f1(tok)) ^ 5614843884653512089)
    return "ANS-%016X" % v, tok


if __name__ == "__main__":
    z = zipfile.ZipFile(sys.argv[1])
    feat = None
    for n in z.namelist():
        b = z.read(n)
        if b[:2] == b"PK":
            zz = zipfile.ZipFile(io.BytesIO(b))
            if "assets/huntress_feature.bin" in zz.namelist():
                feat = zz.read("assets/huntress_feature.bin")
                print("feature.bin from", n, feat.hex())
    c, tok = code(feat)
    print("token", "%x" % tok)
    print(c)
