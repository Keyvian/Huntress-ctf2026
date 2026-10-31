


# ====================================================================================================================
# Day-24 'String Theory' additions ("Count carefully. The comma knows where to stop." = netstrings `<len>:<data>,`).
# warm24.py = warm23x.py (everything above, trailing main() call removed) + this block. ns_parse()/ns_decode() peel one or
# more netstring layers (the single_solve blob was one netstring per character). layers() and line_decode_l() are wrapped
# so the codec works both as a whole-blob layer and as a mixed-codec `NN\t` row codec (label ns), and solve_blob() tries a
# straight netstring peel first because a netstring stream is unambiguous.
# ====================================================================================================================
NS_CHARS = re.compile(rb"^\s*\d{1,9}:")


def ns_parse(b):
    """Return the list of payloads if b is a complete netstring stream, else None."""
    if isinstance(b, str):
        b = b.encode("utf-8", "surrogateescape")
    b = b.strip()
    if not b or not NS_CHARS.match(b):
        return None
    out = []
    i, n_total = 0, len(b)
    while i < n_total:
        j = b.find(b":", i)
        if j <= i or j - i > 9 or not b[i:j].isdigit():
            return None
        n = int(b[i:j])
        end = j + 1 + n
        if end >= n_total + 1 or b[end:end + 1] != b",":
            return None
        out.append(b[j + 1:end])
        i = end + 1
        # tolerate whitespace / newlines between netstrings
        while i < n_total and b[i:i + 1] in (b" ", b"\n", b"\r", b"\t"):
            i += 1
    return out


def ns_decode(b, max_depth=10):
    """Peel netstring layers. Returns (bytes, depth)."""
    cur = b if isinstance(b, (bytes, bytearray)) else b.encode("utf-8", "surrogateescape")
    depth = 0
    while depth < max_depth:
        parts = ns_parse(cur)
        if parts is None:
            break
        cur = b"".join(parts)
        depth += 1
    return cur, depth


_orig_layers23 = layers
_orig_line_decode_l23 = line_decode_l
_orig_solve_blob23 = solve_blob


def layers(s):  # noqa: F811  (wraps the Day-23 version defined above)
    res = []
    parts = ns_parse(s)
    if parts:
        d = b"".join(parts)
        x = inflate(d)
        if x is not None:
            d = x
        u = u16(d)
        if u is not None:
            res.append(u)
        else:
            p = _pr(d)
            if p is not None:
                res.append(p)
        if res:
            return res  # a netstring stream is unambiguous: do not fan out into the rot/atbash/base64 soup
    return res + _orig_layers23(s)


def line_decode_l(f):  # noqa: F811
    out = _orig_line_decode_l23(f)
    ff = f.rstrip("\r\n")
    parts = ns_parse(ff)
    if parts:
        d = b"".join(parts)
        lab = "ns"
        x = inflate(d)
        if x is not None:
            lab, d = lab + "gz", x
        u = u16(d)
        if u is not None:
            lab, d = lab + "16", u
        p = _pr(d)
        if p is not None and p not in [o[1] for o in out]:
            return [(lab, p)] + out
    return out


def solve_blob(raw):  # noqa: F811
    """Netstring-first: peel every netstring layer, then hand the result to the Day-21..23 solver (which also handles a
    non-netstring blob or a netstring stream whose payload is itself another codec)."""
    for _ in range(4):
        d = inflate(raw)
        if d is None:
            break
        raw = d
    dec, depth = ns_decode(raw)
    if depth:
        slug, msg = _orig_solve_blob23(dec)
        if slug:
            return slug, msg
    return _orig_solve_blob23(raw)


if __name__ == "__main__":
    main()
