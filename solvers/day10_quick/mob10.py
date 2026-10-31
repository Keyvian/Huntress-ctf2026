"""Day-9 mobile 'Trust Everyone' (universal mobile puzzle solver, any mode).
APK -> assets/huntress_puzzle.json {codec,data|parts+order} -> ANS-<16 hex>.
usage: mob9.py <challenge> [--submit]   (mastery: one APK per set, delivery = set-1 or nested in one zip)"""
import sys, io, re, json, base64, gzip, codecs, zipfile
sys.path.insert(0, "~/ctf")
from gm import GM

ANS = re.compile(r"ANS-[0-9A-F]{16}")


def dec(codec, data):
    c = (codec or "plain").lower()
    if c == "plain": return data
    if c == "reverse": return data[::-1]
    if c in ("base64", "b64"): return base64.b64decode(data + "=" * (-len(data) % 4)).decode()
    if c in ("base64url", "b64url"): return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4)).decode()
    if c == "hex": return bytes.fromhex(data).decode()
    if c == "rot13": return codecs.encode(data, "rot_13")
    if c == "gzip": return gzip.decompress(base64.b64decode(data)).decode()
    if c == "base32": return base64.b32decode(data + "=" * (-len(data) % 8)).decode()
    raise ValueError(codec)


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
        s = dec(p.get("codec"), s)
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
    ch = sys.argv[1]
    g = GM()
    st = g.start(ch)
    aids = st.get("answer_ids") or ["answer"]
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
    if "--submit" in sys.argv:
        r = g.submit(ch, ans)
        print("SUBMIT", {k: r.get(k) for k in ("result", "flag", "error", "remaining")})
