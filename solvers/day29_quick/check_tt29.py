"""Hand re-implementation of the Day-29 mobile time_trial (v2 analysis, package d29.v2f150b1e8b6b) from the jadx decompile,
used only as an independent cross-check of dalvik.py's interpreted answer. Java long semantics = 64-bit wraparound.
`1 << ((i & 7) * 8)` is an int shift in Java (shift count masked to 5 bits); both readings are printed."""
M = (1 << 64) - 1


def s64(x):
    x &= M
    return x - (1 << 64) if x >> 63 else x


def u(x):
    return x & M


def rotl(x, n):
    x = u(x)
    return u((x << n) | (x >> (64 - n)))


def lsr(x, n):
    return u(x) >> n


def f1(j):
    j2 = u((j + 7517272504460171123) * 7514014913823164051) ^ u(-8882946316355644869)
    j3 = j2 ^ lsr(j2, 11)
    j4 = u((j3 << 5) | lsr(j3, 59)) ^ u(-8081469293569974807)
    j5 = u((j4 << 9) | lsr(j4, 55))
    return u(u((j5 << 60) | lsr(j5, 4)) + 2287174561615152317)


def finBox5b(j):
    j2 = u((j - 6494203186928594556) * 3230814603318712099)
    j3 = u((j2 << 48) | lsr(j2, 16))
    j4 = u((j3 << 54) | lsr(j3, 10)) ^ u(-5302786668278222177)
    j5 = u((j4 << 29) | lsr(j4, 35))
    j6 = j5 ^ lsr(j5, 10)
    j7 = (j6 ^ lsr(j6, 24)) ^ 735058027497780763
    return j7 ^ lsr(j7, 17)


def mixRound49(j):
    j = u(j)
    j2 = u(u(u(u((j ^ lsr(j, 37)) * 5591374049958634043) * 134448088327358411) - 7269339557079963057) * 4160119467352311365)
    j3 = u((j2 << 39) | lsr(j2, 25))
    return u((j3 << 5) | lsr(j3, 59)) ^ 2965847853224104434


def mixTable5d(j):
    j2 = u(u((u(j) ^ u(-158915385194810276)) * u(-5577715858528149429)) - 5893706958303039228)
    j3 = u((j2 << 40) | lsr(j2, 24))
    j4 = u((j3 << 36) | lsr(j3, 28))
    return u(u((j4 << 20) | lsr(j4, 44)) + 5474503373612436485)


def build(j):
    out = []
    j2 = u(j)
    for _ in range(16):
        j2 = u(j2 * 6364136223846793005 + 1442695040888963407)
        out.append(lsr(j2, 29) ^ j2)
    return out


def tableTransform(i, i2):
    return ((i * 257) ^ i2) & 255


def walkSbox52(j, intshift=True):
    j2 = u(j)
    tb = build(3839014703697088740)
    for i in range(8):
        i2 = s64(j2) & 15
        j3 = j2 ^ tb[i2]
        sh = ((i & 7) * 8) & 31 if intshift else (i & 7) * 8
        tt = u(tableTransform(i2, (s64(j3 >> 16)) & 255) * (1 << sh))
        if intshift and sh == 24:
            pass  # int 1<<24 is positive, no sign issue
        jt = j3 ^ tt
        j4 = u((lsr(jt, 8) | u(jt << 56)) * 3856229977046705701)
        j2 = u((j4 ^ lsr(j4, 13)) + i2)
    return j2


def code(intshift=True):
    tok = mixRound49(walkSbox52(mixTable5d(1955915002794568873), intshift))
    v = finBox5b(f1(tok)) ^ 1388381747372643396
    return "ANS-%016X" % v


if __name__ == "__main__":
    print("int-shift ", code(True))
    print("long-shift", code(False))
