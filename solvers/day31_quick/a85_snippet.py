

# ====================================================================================================================
# Day-23 'Eighty-Five Alive' additions ("The alphabet got bigger. Adobe might recognize the neighbors." = Ascii85 / base85).
# warm23.py = warm21.py (everything above, trailing main() call removed) + this block. a85_candidates() tries Adobe Ascii85
# (`<~ ... ~>` framing), bare Ascii85 (`!`..`u`), RFC-1924 / Python base85 and Z85; layers() and line_decode_l() are wrapped so
# the new codecs work both as a whole-blob layer and as a mixed-codec `NN\t` row codec (labels a85 / a85b / b85 / z85).
# ====================================================================================================================
_Z85 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"
A85_CHARS = re.compile(r"^[!-uzy\s]+$")
B85_CHARS = re.compile(r"^[0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~\s]+$")
Z85_CHARS = re.compile(r"^[0-9A-Za-z.\-:+=^!/*?&<>()\[\]{}@%$#\s]+$")


def _z85dec(s):
    s = re.sub(r"\s+", "", s)
    if len(s) % 5:
        return None
    out = bytearray()
    for i in range(0, len(s), 5):
        v = 0
        for ch in s[i:i + 5]:
            v = v * 85 + _Z85.index(ch)
        if v > 0xFFFFFFFF:
            return None
        out += v.to_bytes(4, "big")
    return bytes(out)


def a85_candidates(t):
    """[(label, bytes)] base-85 decodings of a text blob (Adobe-framed first)."""
    out = []
    s = t.strip()
    framed = s.startswith("<~") and s.endswith("~>")
    if framed:
        try:
            out.append(("a85", base64.a85decode(s, adobe=True, ignorechars=b" \t\n\r\v")))
        except Exception:
            pass
        inner = s[2:-2]
    else:
        inner = s
    if A85_CHARS.match(inner) and len(re.sub(r"\s+", "", inner)) >= 5:
        try:
            d = base64.a85decode(inner, adobe=False, ignorechars=b" \t\n\r\v")
            if not any(d == x for _, x in out):
                out.append(("a85b", d))
        except Exception:
            pass
    if not framed and B85_CHARS.match(s) and len(re.sub(r"\s+", "", s)) >= 5:
        try:
            out.append(("b85", base64.b85decode(re.sub(r"\s+", "", s))))
        except Exception:
            pass
    if not framed and Z85_CHARS.match(s):
        try:
            d = _z85dec(s)
            if d is not None:
                out.append(("z85", d))
        except Exception:
            pass
    return out


def _printable85(b):
    try:
        x = b.decode("utf-8")
    except Exception:
        return False
    return bool(x) and sum(ch.isprintable() or ch in "\r\n\t" for ch in x) > 0.95 * len(x)


_orig_layers = layers
_orig_line_decode_l = line_decode_l


def layers(s):  # noqa: F811  (wraps the Day-21 version defined above)
    t = re.sub(r"^\d+\t", "", s.strip())
    res = []
    for lab, d in a85_candidates(t):
        for _ in range(4):
            x = inflate(d)
            if x is None:
                break
            d = x
        u = u16(d)
        if u is not None:
            res.append(u); continue
        if _printable85(d):
            res.append(d.decode("utf-8"))
    if res and t.strip().startswith("<~"):
        return res  # an Adobe-framed blob is unambiguous: do not fan out into the rot/atbash/base64 soup
    return res + _orig_layers(s)


def line_decode_l(f):  # noqa: F811
    out = _orig_line_decode_l(f)
    ff = f.rstrip("\r\n")
    extra = []
    for lab, d in a85_candidates(ff):
        x = inflate(d)
        if x is not None:
            lab, d = lab + "gz", x
        u = u16(d)
        if u is not None:
            lab, d = lab + "16", u
        p = _pr(d)
        if p is not None and p not in [o[1] for o in out] and p not in [o[1] for o in extra]:
            extra.append((lab, p))
    if ff.strip().startswith("<~") and extra:
        return extra + out  # framed Ascii85 row: its decode goes first
    return out + extra


main()
