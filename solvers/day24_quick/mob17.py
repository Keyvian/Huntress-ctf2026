"""Day-17 mobile 'Name Collapse': mob15 + NEW codec "indexed" -> {codec:"indexed", data:"<scrambled 20 chars>", order:[...]}.
Scatter rule out[order[i]] = data[i] (graded day 17); gather rule out[i] = data[order[i]] kept as fallback; the ANS-<16 HEX>
pattern picks the right one. Decoy chars (data longer than order) are dropped by either rule. The dex is just a WebView stub
(R8-style renamed class `a` holds only constants) and the 127.0.0.1:19090 backend is a decoy.
mob15: codec "native" (arena_value in lib/<abi>/*.so); mob14: "caesar"; earlier: plain/reverse/base64/base64url/hex/rot13/gzip/
base32/xor/split.
usage: mob17.py <challenge> [--submit] [--retry|--practice] [--local apk...]"""
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


def indexed_dec(data, order):
    """day-17 'indexed': scatter (out[order[i]] = data[i]) first, gather (out[i] = data[order[i]]) as fallback."""
    cands = []
    if order:
        n = max(order) + 1
        out = [None] * n
        for i, o in enumerate(order):
            if i < len(data):
                out[o] = data[i]
        cands.append("".join(c for c in out if c is not None))
        cands.append("".join(data[o] for o in order if o < len(data)))
    for s in cands:
        if ANS.fullmatch(s.strip()):
            return s.strip()
    return cands[0] if cands else data


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
    if c in ("indexed", "index", "permute", "permutation", "shuffle", "scatter"): return indexed_dec(data, p.get("order") or p.get("index") or p.get("map"))
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


def native_answers(z):
    """[(lib path, value)] for each challenge-owned .so (exports huntress_arena_*)."""
    from elftools.elf.elffile import ELFFile
    out = []
    for n in z.namelist():
        if not (n.startswith("lib/") and n.endswith(".so")):
            continue
        b = z.read(n)
        if b"huntress_arena" not in b:
            continue
        val = None
        try:
            e = ELFFile(io.BytesIO(b))
            st = e.get_section_by_name(".symtab")
            for sym in (st.iter_symbols() if st else []):
                if sym.name == "arena_value" and sym["st_size"]:
                    for sec in e.iter_sections():
                        a, sz = sec["sh_addr"], sec["sh_size"]
                        if sec["sh_type"] != "SHT_NOBITS" and a <= sym["st_value"] < a + sz:
                            o = sec["sh_offset"] + sym["st_value"] - a
                            val = b[o:o + sym["st_size"]].split(bytes(1))[0].decode("latin1")
        except Exception as ex:
            print("elf parse", n, ex)
        if not val or not ANS.fullmatch(val):
            m = ANS.findall(b.decode("latin1"))
            val = m[0] if m else val
        out.append((n, val))
    return out


def puzzle_answer(apk):
    z = zipfile.ZipFile(io.BytesIO(apk))
    p = json.loads(z.read("assets/huntress_puzzle.json"))
    if (p.get("codec") or "").lower() == "native":
        nat = native_answers(z)
        vals = sorted({v for _, v in nat if v and ANS.fullmatch(v)})
        print("  native libs", nat, "json data", p.get("data"))
        if len(vals) == 1:
            if p.get("data") != vals[0]: print("  WARN json data != native value")
            return vals[0], p
        if ANS.fullmatch(str(p.get("data", "")).strip()):
            return p["data"].strip(), p
        return "NATIVE?", p
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
    raw0 = g.artifact(ch)
    if "--save" in sys.argv:
        sd = sys.argv[sys.argv.index("--save") + 1]; os.makedirs(sd, exist_ok=True)
        json.dump(st, open(os.path.join(sd, "start.json"), "w"))
        open(os.path.join(sd, "artifact.bin"), "wb").write(raw0)
    apks = apks_from(raw0)
    if len(apks) < len(aids):
        for d in range(1, len(aids)):
            try:
                apks += apks_from(g.artifact(ch, d))
            except Exception as e:
                print("delivery", d, "ERR", e)
    ans = {}
    for i, a in enumerate(aids):
        s, p = puzzle_answer(apks[min(i, len(apks) - 1)][1])
        print(a, apks[min(i, len(apks) - 1)][0], p.get("codec"), s, p.get("order"))
        ans[a] = s
    print("compute %.2fs" % (time.time() - t0))
    if not all(ANS.fullmatch(v) for v in ans.values()):
        print("ABORT: not all answers match ANS pattern"); sys.exit(2)
    if "--submit" in sys.argv:
        r = g.submit(ch, ans)
        print("SUBMIT", {k: r.get(k) for k in ("result", "flag", "error", "remaining")}, "%.2fs" % (time.time() - t0))
