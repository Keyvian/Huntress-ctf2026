"""Day-20 mobile 'Loaded Later': mob19 + NEW codec "dynamic" -> {codec:"dynamic", data:"assets/payload.dex"}.
`data` is the APK member path of a secondary DEX ("challenge-signed module"); the answer is the static final String ANSWER
of its only class (com.huntress.arena.payload.Module). Decoding = parse the DEX string table + the class static_values
(encoded_array) to map static field names -> string constants, prefer the field named ANSWER, else the unique ANS-<16 HEX>
string. Fallbacks: member may be gzip / base64 / xor(key) wrapped, or a nested zip/jar holding classes.dex.
Nothing is executed. mob19/mob17 codecs (plain/reverse/base64/base64url/hex/rot13/gzip/base32/xor/caesar/split/indexed/
native/reflection) are reused unchanged.
usage: mob20.py <challenge> [--submit] [--retry|--practice] [--save dir] | mob20.py --local apk..."""
import sys, os, io, re, json, base64, gzip, zipfile, binascii, time, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mob19
from mob19 import ANS, apks_from, _key_bytes

DEX_MAGIC = b"dex\n"


def _uleb(b, o):
    v = 0; s = 0
    while True:
        c = b[o]; o += 1
        v |= (c & 0x7f) << s; s += 7
        if not c & 0x80:
            return v, o


def dex_strings(b):
    n, off = struct.unpack_from("<II", b, 0x38)
    out = []
    for i in range(n):
        so = struct.unpack_from("<I", b, off + 4 * i)[0]
        _, p = _uleb(b, so)
        e = b.index(b"\x00", p)
        out.append(b[p:e].decode("utf-8", "replace"))
    return out


def dex_static_strings(b):
    """{class descriptor: {static field name: string value}} from every class_def's static_values encoded_array."""
    strs = dex_strings(b)
    tn, to = struct.unpack_from("<II", b, 0x40)
    types = [strs[struct.unpack_from("<I", b, to + 4 * i)[0]] for i in range(tn)]
    fn, fo = struct.unpack_from("<II", b, 0x50)
    fields = [struct.unpack_from("<HHI", b, fo + 8 * i) for i in range(fn)]  # class_idx, type_idx, name_idx
    cn, co = struct.unpack_from("<II", b, 0x60)
    out = {}
    for i in range(cn):
        (cls_idx, _acc, _sup, _ifs, _src, _ann, cdata, svals) = struct.unpack_from("<8I", b, co + 32 * i)
        if not cdata:
            continue
        o = cdata
        nsf, o = _uleb(b, o); _nif, o = _uleb(b, o); _nd, o = _uleb(b, o); _nv, o = _uleb(b, o)
        names = []; fidx = 0
        for _ in range(nsf):
            d, o = _uleb(b, o); _af, o = _uleb(b, o)
            fidx += d
            names.append(strs[fields[fidx][2]])
        vals = []
        if svals:
            p = svals
            cnt, p = _uleb(b, p)
            for _ in range(cnt):
                h = b[p]; p += 1
                vt, va = h & 0x1f, h >> 5
                if vt == 0x17:  # VALUE_STRING
                    idx = int.from_bytes(b[p:p + va + 1], "little"); p += va + 1
                    vals.append(strs[idx] if idx < len(strs) else None)
                elif vt in (0x1e, 0x1f):
                    vals.append(None if vt == 0x1e else bool(va))
                elif vt in (0x1c, 0x1d):
                    break  # array / annotation: stop mapping (not expected here)
                else:
                    vals.append(int.from_bytes(b[p:p + va + 1], "little")); p += va + 1
        out[types[cls_idx]] = {n: (vals[k] if k < len(vals) else None) for k, n in enumerate(names)}
    return out


def unwrap(b, p):
    """bytes of the loaded module -> DEX bytes (gzip / base64 / xor / zip-with-classes.dex wrappers)."""
    for _ in range(4):
        if b[:4] == DEX_MAGIC:
            return b
        if b[:2] == b"\x1f\x8b":
            b = gzip.decompress(b); continue
        if b[:2] == b"PK":
            z = zipfile.ZipFile(io.BytesIO(b))
            dn = [n for n in z.namelist() if n.endswith(".dex")]
            if dn:
                b = z.read(dn[0]); continue
        t = b.strip()
        if re.fullmatch(rb"[A-Za-z0-9+/=_\-\s]+", t) and len(t) > 16:
            try:
                b = base64.b64decode(t + b"=" * (-len(t) % 4)); continue
            except Exception:
                pass
        if p.get("key") is not None:
            kb = _key_bytes(p["key"])
            b = bytes(c ^ kb[i % len(kb)] for i, c in enumerate(b)); continue
        break
    return b


def dynamic_answer(z, p):
    path = str(p.get("data") or p.get("path") or p.get("module") or "").lstrip("/")
    names = z.namelist()
    cands = [path, "assets/" + path] + [n for n in names if n.endswith(path)]
    member = next((n for n in cands if n in names), None)
    if member is None:
        member = next((n for n in names if n.endswith(".dex") and n != "classes.dex"), None)
    b = unwrap(z.read(member), p)
    print("  dynamic module", member, len(b), "dex" if b[:4] == DEX_MAGIC else "?")
    if b[:4] == DEX_MAGIC:
        try:
            cls = dex_static_strings(b)
            print("  static strings", json.dumps(cls)[:400])
            for c, f in cls.items():
                for k in ("ANSWER", "answer", "ANS", "VALUE", "CODE"):
                    v = f.get(k)
                    if isinstance(v, str) and ANS.fullmatch(v.strip()):
                        return v.strip()
            vals = [v for f in cls.values() for v in f.values() if isinstance(v, str) and ANS.fullmatch(v.strip())]
            if len(set(vals)) == 1:
                return vals[0].strip()
        except Exception as ex:
            print("  dex parse failed:", ex)
    m = ANS.findall(b.decode("latin1"))
    if len(set(m)) == 1:
        return m[0]
    print("  WARN ambiguous ANS candidates", m)
    return m[-1] if m else "DYNAMIC?"


_orig_puzzle_answer = mob19.puzzle_answer


def puzzle_answer(apk):
    z = zipfile.ZipFile(io.BytesIO(apk))
    p = json.loads(z.read("assets/huntress_puzzle.json"))
    if (p.get("codec") or "").lower() in ("dynamic", "dex", "secondary_dex", "dynamic_dex", "loaded"):
        return dynamic_answer(z, p), p
    return _orig_puzzle_answer(apk)


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
    body = {"op": op, "challenge": ch}
    if "--run-for-time" in sys.argv:
        body["run_for_time"] = True
    st = g.post(body)
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
                b = g.artifact(ch, d)
                if "--save" in sys.argv:
                    open(os.path.join(sd, "artifact%d.bin" % d), "wb").write(b)
                apks += apks_from(b)
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
