"""Hand port of the Day-31 mastery set-10 APK (Day-20 dynamic dex theme, package ...d20.va7e2904c53ba), from jadx output, to cross-check
dalvik.py + the mob31 loader model. Constants are for that one attempt only."""
M = (1 << 64) - 1


def s(x):
    return x & M


def rol(x, n):
    x &= M
    return ((x << n) | (x >> (64 - n))) & M


def mixLater36(j):
    j2 = s(s(j - 2598963766429029958) * -2314442298387635251)
    j3 = s(rol(j2, 14) * 6152621727512432979)
    j4 = (j3 ^ (j3 >> 24)) ^ s(-6724674977345964115)
    return rol(j4, 34)


def share(j):
    j2 = s(s((j ^ s(-5446988181864545298)) + 7734352788631645641) - 8804960127803506757)
    j3 = s(s(rol(j2, 33) * 9180210778270305715) + 1694110653247294577)
    return (j3 ^ (j3 >> 17)) ^ 192009136668948296


def mixModuleb1(j):
    j2 = s((j ^ 2539599717544961258) + 4352987922722255220) ^ s(-5496931249528959757)
    j3 = s(rol(j2, 25) * 6870656559026291731)
    return (j3 ^ (j3 >> 7)) ^ 5356522948158692433 ^ 1603567203673657057


def f1(j):
    j2 = s(s(s(j * 4320778246080218583) + 7881487432248539081) * -3844811116225974655)
    j3 = s(rol(j2, 28) * -7052732914694674351)
    j4 = j3 ^ (j3 >> 29)
    j5 = s(rol(j4, 38) * 4337933649120198711)
    return j5 ^ (j5 >> 22)


def finLoaderfc(j):
    j2 = s(s((j ^ (j >> 41)) * 1399010718354872825) - 1775576874178565012)
    j3 = rol(j2, 39)
    j4 = j3 ^ (j3 >> 28)
    j5 = j4 ^ (j4 >> 36)
    return (j5 ^ (j5 >> 34)) ^ 2462492946365575101


tok = mixModuleb1(share(mixLater36(s(-6000015034297807931))))
v = finLoaderfc(f1(tok)) ^ s(-2202333561025215760)
print("ANS-%016X" % v)
