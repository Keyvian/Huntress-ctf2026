"""Hand re-implementation (from jadx) of the time_trial v2 analysis APK, to cross-check dalvik.py. Only valid for that one attempt's
constants. Chain: token = mixStack0d(peelStack67(mixLayer64(seed))); code = finPeelcb(Mix.f1(token)) ^ const -> 16 hex."""
M = (1 << 64) - 1


def rol(x, n):
    return ((x << n) | (x >> (64 - n))) & M


def s(x):
    return x & M


def mixLayer64(j):
    j2 = s((j + 5815351720327509031) * 4650533673348281233)
    j3 = rol(j2, 5) ^ 5502430947777448911
    return j3 ^ (j3 >> 10)


def layeredGate(i, i2, i3):
    return ((i ^ i2) + i3) % 31


def peelStack67(j):
    j2 = 0
    for i in range(8):
        j2 |= (((j >> (i * 8)) & 255) ^ ((4 + i) & 255)) << (i * 8)
    j3 = 0
    for i in range(8):
        j3 = s(j3 << 8) | ((j2 >> (i * 8)) & 255)
    return s(j3 + layeredGate(j3 & 255, (j3 >> 8) & 255, (j3 >> 16) & 255) * 4225323071727454139)


def mixStack0d(j):
    j2 = s((j ^ s(-4005669329108898906)) * s(-5331508655071329335)) ^ s(-9066911443427311897)
    j3 = rol(j2, 47)
    return rol(j3, 50)


def f1(j):
    j2 = (j ^ (j >> 27)) ^ s(-1658035572676510392)
    j3 = s(rol(j2, 42) * s(-2022055998700016049) + 7735372352877875925)
    j4 = rol(j3, 11)
    return rol(j4, 61)


def finPeelcb(j):
    j2 = j ^ s(-4451391240684418338)
    j3 = rol(j2, 6)
    j4 = s(rol(j3, 41) - 8370247859523084148)
    j5 = (j4 ^ (j4 >> 28)) ^ s(-4780434040759614759)
    j6 = j5 ^ (j5 >> 17)
    j7 = s((j6 ^ (j6 >> 41)) * s(-6142756028026967099))
    j8 = j7 ^ (j7 >> 39)
    return rol(j8, 13)


token = mixStack0d(peelStack67(mixLayer64(6335381668636147072)))
print("token %x" % token)
print("ANS-%016X" % (finPeelcb(f1(token)) ^ s(-8602376142503676710)))
