"""Day-14 mobile 'Predictable Crypto' (universal mobile puzzle solver, any mode). mob13 + NEW codec "caesar" (char code - key on the
printable-ASCII ring 32..126; key e.g. 9). The seeded-nonce/weak-derivation story is a decoy.
APK -> assets/huntress_puzzle.json {codec,data[,key]|parts+order} -> ANS-<16 hex>.
usage: mob13.py <challenge> [--submit] [--local apk...]"""
import sys, os, io, re, json, base64, gzip, codecs, zipfile, binascii, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

ANS = re.compile(r"ANS-[0-9A-F]{16}")


def _bytes(data):
    """raw bytes of an encoded data field: base64 / base64url / hex."""
    d = data.strip()
    if re.fullmatch(r"([0-9a-fA-F]{2})+", d):
        yield binascii.unhexlify(d)
    for f in (base64.b64decode, base64.urlsafe_b64decode):
        try: yield f(d + "=" * (-len(d) % 4))
        except Exception: pass
    yield d.encode("latin1", "replace")


def _key_bytes(key):
    if isinstance(key, int): return bytes([key & 0xff])
    if isinstance(key, list): return bytes(k & 0xff for k in key)
    k = str(key)
    if re.fullmatch(r"\d+", k): return bytes([int(k) & 0xff])
    if re.fullmatch(r"0x[0-9a-fA-F]+", k): return bytes([int(k, 16) & 0xff])
    if re.fullmatch(r"([0-9a-fA-F]{2})+", k) and len(k) > 2: return binascii.unhexlify(k)
    return k.encode()


def xor_dec(data, key):
    kb = _key_bytes(key)
    for raw in _bytes(data):
        s = bytes(c ^ kb[i % len(kb)] for i, c in enumerate(raw)).decode("latin1")
        if ANS.fullmatch(s.strip()):
            return s
    raw = next(_bytes(data))
    return bytes(c ^ kb[i % len(kb)] for i, c in enumerate(raw)).decode("latin1")


def dec(codec, data, p):
    c = (codec or "plain").lower()
    if c == "plain": return data
    if c == "reverse": return data[::-1]
    if c in ("base64", "b64"): return base64.b64decode(data + "=" * (-len(data) % 4)).decode()
    if c in ("base64url", "b64url"): return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4)).decode()
    if c == "hex": return bytes.fromhex(data).decode()
    if c == "rot13": return codecs.encode(data, "rot_13")
    if c == "gzip": return gzip.decompress(base64.b64decode(data)).decode()
    if c == "base32": return base64.b32decode(data + "=" * (-len(data) % 8)).decode()
    if c == "xor": return xor_dec(data, p.get("key"))
    if c in ("caesar", "shift", "rot"): return caesar_dec(data, p.get("key"))
    raise ValueError(codec)


def caesar_dec(data, key):
    """day-14 'caesar': every char code shifted by key (printable ASCII 32..126 ring); fallbacks: mod 256, letters-only."""
    k = int(_key_bytes(key)[0]) if not isinstance(key, int) else key
    cands = [
        "".join(chr((ord(ch) - 32 - k) % 95 + 32) for ch in data),
        "".join(chr((ord(ch) - k) % 256) for ch in data),
    ]
    az, AZ = "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    sk = k % 26
    cands.append(data.translate(str.maketrans(az + AZ, az[-sk:] + az[:-sk] + AZ[-sk:] + AZ[:-sk])))
    for s in cands:
        if ANS.fullmatch(s.strip()):
            return s
    return cands[0]


def puzzle_answer(apk):
    z = zipfile.ZipFile(io.BytesIO(apk))
    p = json.loads(z.read("assets/huntress_puzzle.json"))
    if p.get("codec") == "split" or "parts" in p:
        parts, order = p["parts"], p.get("order", list(range(len(p["parts"]))))
        out = [None] * len(parts)
        for i, o in enumerate(order):
            out[o] = parts[i]
        s = "".join(out)
        if not ANS.fullmatch(s):
            alt = "".join(parts[o] for o in order)
            s = alt if ANS.fullmatch(alt) else s
        return s, p
    s = p["data"]
    for _ in range(6):
        if ANS.fullmatch(s.strip()):
            return s.strip(), p
        s = dec(p.get("codec"), s, p)
    return s, p


def apks_from(raw):
    out = []
    z = zipfile.ZipFile(io.BytesIO(raw))
    names = z.namelist()
    if "assets/huntress_puzzle.json" in names:
        return [("apk", raw)]
    for n in names:
        b = z.read(n)
        if b[:2] == b"PK":
            out += [(n + ":" + a, x) for a, x in apks_from(b)]
    return out


if __name__ == "__main__":
    if sys.argv[1] == "--local":
        for f in sys.argv[2:]:
            for n, a in apks_from(open(f, "rb").read()):
                s, p = puzzle_answer(a)
                print(f, n, p.get("codec"), s, bool(ANS.fullmatch(s)))
        sys.exit(0)
    from gmx import GMX
    ch = sys.argv[1]
    t0 = time.time()
    g = GMX()
    op = "start"
    for o in ("retry", "practice"):
        if "--" + o in sys.argv: op = o
    st = g.post({"op": op, "challenge": ch})
    aids = st.get("answer_ids") or []
    print("mode", st.get("mode"), "deadline", st.get("deadline"), "uar", st.get("unique_attempts_remaining"), "ids", aids)
    if not aids:
        print({k: v for k, v in st.items() if k != "guidance"}); sys.exit(1)
    apks = apks_from(g.artifact(ch))
    if len(apks) < len(aids):
        for d in range(1, len(aids)):
            try:
                apks += apks_from(g.artifact(ch, d))
            except Exception as e:
                print("delivery", d, "ERR", e)
    ans = {}
    for i, a in enumerate(aids):
        s, p = puzzle_answer(apks[min(i, len(apks) - 1)][1])
        print(a, apks[min(i, len(apks) - 1)][0], p.get("codec"), s)
        ans[a] = s
    print("compute %.2fs" % (time.time() - t0))
    if not all(ANS.fullmatch(v) for v in ans.values()):
        print("ABORT: not all answers match ANS pattern"); sys.exit(2)
    if "--submit" in sys.argv:
        r = g.submit(ch, ans)
        print("SUBMIT", {k: r.get(k) for k in ("result", "flag", "error", "remaining")}, "%.2fs" % (time.time() - t0))
