"""Static (no-execution) decoders for the Huntress script-analysis specimens.
decode_specimen(name, text) -> dict(plan=<dict of k=v>, raw=<decoded text>, codec=..., rep=..., xf=..., kind=...)"""
import re, json, base64, binascii, urllib.parse, itertools


def _printable(bs):
    return all(32 <= b < 127 or b in (9, 10, 13) for b in bs)


def _plan_like(bs):
    if not bs or not _printable(bs):
        return False
    t = bytes(bs).decode("ascii")
    if re.match(r"\s*\{", t):
        try:
            return isinstance(json.loads(t), dict)
        except Exception:
            return False
    return bool(re.match(r"\s*v=\d+\|", t)) and ("campaign" in t or "steps" in t)


def parse_plan(t):
    t = t.strip()
    if t.startswith("{"):
        try:
            return json.loads(t)
        except Exception:
            pass
    d = {}
    for part in t.split("|"):
        if "=" in part:
            k, v = part.split("=", 1)
            d[k] = v
    return d


def nums_from(material, rep=""):
    """Return candidate integer lists (both orderings) for a material string, representation-agnostic."""
    m = material.strip().replace("\\\\", "\\")
    outs = []

    def add(x):
        if x and all(isinstance(v, int) and 0 <= v < 65536 for v in x) and x not in outs:
            outs.append(x)
    if m.startswith("["):
        try:
            items = json.loads(m)
            if all(isinstance(i, int) for i in items):
                add(items)
            else:
                ss = [str(i) for i in items]
                try: add([int(s, 16) for s in ss])
                except Exception: pass
                try: add([int(s) for s in ss])
                except Exception: pass
        except Exception:
            body = m.strip("[]")
            toks = [t.strip().strip("\"'") for t in body.split(",") if t.strip()]
            try: add([int(t, 0) for t in toks])
            except Exception: pass
    if re.search(r"\\x[0-9a-fA-F]{2}", m):
        add([int(h, 16) for h in re.findall(r"\\x([0-9a-fA-F]{2})", m)])
    if re.search(r"\\[0-7]{3}", m):
        add([int(h, 8) for h in re.findall(r"\\([0-7]{3})", m)])
    if re.search(r"%[0-9a-fA-F]{2}", m):
        add([int(h, 16) for h in re.findall(r"%([0-9a-fA-F]{2})", m)])
    if re.search(r"\\u[0-9a-fA-F]{4}", m):
        add([int(h, 16) for h in re.findall(r"\\u([0-9a-fA-F]{4})", m)])
    toks = [t for t in re.split(r"[^0-9A-Za-z]+", m) if t]
    if len(toks) > 4:
        if all(t.isdigit() for t in toks):
            add([int(t) for t in toks])
        if all(re.fullmatch(r"(?:0x)?[0-9a-fA-F]{1,2}", t) for t in toks):
            add([int(t, 16) for t in toks])
        if all(re.fullmatch(r"&H[0-9a-fA-F]+|[0-9]+", t) for t in toks):
            pass
    if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", m):
        add(list(bytes.fromhex(m)))
    if re.fullmatch(r"[A-Za-z0-9+/=_\-\s]+", m) and len(m) >= 8:
        c = re.sub(r"\s", "", m)
        for cc in (c, c[::-1]):  # also string-reversed base64 (reversed_base64)
            try:
                add(list(base64.b64decode(cc.replace("-", "+").replace("_", "/") + "=" * (-len(cc) % 4), validate=False)))
            except Exception:
                pass
        if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", c[::-1]):
            add(list(bytes.fromhex(c[::-1])))
        try:
            add(list(base64.b32decode(c + "=" * (-len(c) % 8))))
        except Exception:
            pass
    res = []
    for o in outs:
        res.append(o)
        res.append(o[::-1])
    return res


def literals(text):
    """Long string literals (adjacent literals concatenated, e.g. Python ("a" "b")) and numeric arrays."""
    out = []
    for mm in re.finditer(r"\"[^\"\\\n]*\"(?:\s*(?:\+|&|\.\.|\.)\s*_?\s*\"[^\"\\\n]*\")+", text):  # "a" + "b" (JS/VBS/Lua/PHP concat)
        out.append("".join(re.findall(r"\"([^\"\\\n]*)\"", mm.group(0))))
    for mm in re.finditer(r"\(\s*((?:[rbu]?\"[^\"\n]*\"\s*)+)\)", text):
        parts = re.findall(r"\"([^\"\n]*)\"", mm.group(1))
        if len(parts) > 1:
            out.append("".join(parts))
    for mm in re.finditer(r"\"((?:[^\"\\\n]|\\.){40,})\"|'((?:[^'\\\n]|\\.){40,})'", text):
        out.append(mm.group(1) if mm.group(1) is not None else mm.group(2))
    for mm in re.finditer(r"\[\s*([0-9xXa-fA-F\"'\s,]{60,})\]", text):
        out.append("[" + mm.group(1) + "]")
    for mm in re.finditer(r"\(\s*((?:\d{1,3}\s*,\s*){15,}\d{1,3})\s*,?\s*\)", text):
        out.append("[" + mm.group(1) + "]")
    return sorted(set(out), key=len, reverse=True)


def inverse_candidates(arr, keys):
    """Yield (xf_name, key, decoded list)."""
    yield ("identity", None, arr)
    ks = sorted(set(k % 256 for k in keys))
    for k in ks:
        yield ("sub", k, [(n - k) % 256 for n in arr])
        yield ("add", k, [(n + k) % 256 for n in arr])
        yield ("xor", k, [n ^ k for n in arr])
        # rolling xor variants
        r, kk = [], k
        for n in arr:
            v = n ^ kk; r.append(v); kk = n
        yield ("rolling_cipher_prev", k, r)
        r, kk = [], k
        for n in arr:
            v = n ^ kk; r.append(v); kk = v
        yield ("rolling_plain_prev", k, r)
        yield ("xor_inc", k, [n ^ ((k + i) % 256) for i, n in enumerate(arr)])
    for s in range(1, 8):
        yield ("rotr", s, [((n >> s) | (n << (8 - s))) & 0xFF for n in arr])
        yield ("rotl", s, [((n << s) | (n >> (8 - s))) & 0xFF for n in arr])
    for L in range(2, 9):
        for combo in _key_seqs(keys, L):
            yield ("repxor", combo, [n ^ combo[i % len(combo)] for i, n in enumerate(arr)])


_KS = {}


def _key_seqs(keys, L):
    return [tuple(c) for c in _KS.get(L, [])]


def brute(arr_cands, keys, keyseqs=()):
    for arr in arr_cands:
        for name, k, out in inverse_candidates(arr, keys):
            if all(0 <= x < 256 for x in out) and _plan_like(out):
                return name, k, bytes(out).decode("ascii")
        for seq in keyseqs:
            if seq:
                out = [n ^ seq[i % len(seq)] for i, n in enumerate(arr)]
                if _plan_like(out):
                    return "repxor", seq, bytes(out).decode("ascii")
                # rolling/sub with seq not needed
    return None, None, None


def ints_in(text):
    vals = set()
    for m in re.finditer(r"\b0x([0-9a-fA-F]+)\b|&H([0-9a-fA-F]+)\b|\b(\d{1,3})\b", text):
        try:
            v = int(m.group(1) or m.group(2), 16) if (m.group(1) or m.group(2)) else int(m.group(3))
            if 0 <= v < 256:
                vals.add(v)
        except Exception:
            pass
    return vals


def key_lists(text):
    seqs = []
    for m in re.finditer(r"[\(\[\{]\s*((?:(?:0x[0-9a-fA-F]+|&H[0-9a-fA-F]+|\d{1,3})\s*,\s*){1,15}(?:0x[0-9a-fA-F]+|&H[0-9a-fA-F]+|\d{1,3}))\s*,?\s*[\)\]\}]", text):
        items = [x.strip() for x in m.group(1).split(",")]
        try:
            seq = tuple(int(x, 16) if x.lower().startswith("0x") else int(x[2:], 16) if x.startswith("&H") else int(x) for x in items)
            if all(0 <= v < 256 for v in seq) and 2 <= len(seq) <= 16:
                seqs.append(seq)
        except Exception:
            pass
    # Array(…) in VBS
    for m in re.finditer(r"Array\(([^)]*)\)", text):
        items = [x.strip() for x in m.group(1).split(",") if x.strip()]
        try:
            seq = tuple(int(x[2:], 16) if x.startswith("&H") else int(x, 0) for x in items)
            if all(0 <= v < 256 for v in seq) and len(seq) >= 2:
                seqs.append(seq)
        except Exception:
            pass
    return seqs


# Day-19 (Sharp Practice): the header can sit INSIDE a C# string literal of an ASPX host
# ("// HUNTRESS_ANALYSIS_V1:HEX-<payload>\n#nullable ...") -> stop the payload at a backslash too.
ANALYSIS = re.compile(r"HUNTRESS_ANALYSIS_V1:([A-Z0-9]+)-([^\s\"'<>\]\\]+)")


def decode_analysis(enc, payload):
    e = enc.upper()
    try:
        if e == "B64":
            return base64.b64decode(payload + "=" * (-len(payload) % 4)).decode()
        if e == "HEX":
            return bytes.fromhex(payload).decode()
        if e == "HB64":
            return base64.b64decode(bytes.fromhex(payload).decode()).decode()
        if e == "URL":
            return urllib.parse.unquote(payload)
        if e == "B64HEX":
            return bytes.fromhex(base64.b64decode(payload).decode()).decode()
        if e == "FRAG":
            return bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", payload)).decode()
    except Exception:
        return None
    return None


SPLIT_ARRAY = re.compile(r"HUNTRESS_ANALYSIS_V1_SPLIT_\w+\s*=\s*\[(.*?)\]", re.S)


def split_header(text):
    """Day-18 Google Apps Script form: '// HUNTRESS_ANALYSIS_V1:SPLIT' + const HUNTRESS_ANALYSIS_V1_SPLIT_<id> = ["ENC-...", ...].join("").
    Returns the reassembled 'ENC-payload' string or None."""
    if "HUNTRESS_ANALYSIS_V1:SPLIT" not in text:
        return None
    m = SPLIT_ARRAY.search(text)
    if not m:
        return None
    parts = re.findall(r"\"([^\"]*)\"|'([^']*)'", m.group(1))
    joined = "".join(a if a else b for a, b in parts)
    return joined if re.match(r"[A-Z0-9]+-", joined) else None


def decode_specimen(name, text):
    out = dict(kind=None, plan={}, raw=None, codec=None, rep=None, xf=None, xf_found=None)
    sp = split_header(text)
    if sp:
        enc, payload = sp.split("-", 1)
        raw = decode_analysis(enc, payload)
        out.update(kind="analysis", enc=enc, raw=raw, plan=parse_plan(raw) if raw else {})
        if raw:
            return out
    m = ANALYSIS.search(text)
    if m:
        raw = decode_analysis(m.group(1), m.group(2))
        if raw is None and m.group(1).upper() == "FRAG":
            raw = None
        out.update(kind="analysis", enc=m.group(1), raw=raw, plan=parse_plan(raw) if raw else {})
        if raw:
            return out
    # Batch FrAg fragments (plain plan split into set lines)
    if name.lower().endswith((".bat", ".cmd")):
        vals = {}
        sect = text.split(":HUNTRESS_INSPECT", 1)[-1].split(":HUNTRESS_SEPARATOR_DONE", 1)[0]
        for line in sect.splitlines():
            mm = re.match(r'\s*set\s+"?([A-Za-z_][A-Za-z_0-9]*?)(\d+)=(.*)', line, re.I)
            if mm and re.search(r"![A-Za-z_]\w*!|%%?[A-Za-z_]\w*%%?", mm.group(3)) and not re.search(r"=", mm.group(3).replace("^|", "")):
                continue  # reassembly line (references other variables), not a fragment
            if mm and not re.search(r"ready|dead|neutral", mm.group(1), re.I):
                v = mm.group(3)
                if line.strip().lower().startswith('set "'):
                    v = v.rsplit('"', 1)[0]
                vals.setdefault(mm.group(1).lower(), {})[int(mm.group(2))] = v.replace("^|", "|").replace("^&", "&").replace("^^", "^")
        best = None
        for pre, d in vals.items():
            t = "".join(d[k] for k in sorted(d))
            if t.startswith("v=") and (best is None or len(t) > len(best)):
                best = t
        cm = re.search(r"HUNTRESS-CODEC:([^\r\n]*)", text)
        out.update(kind="batch", raw=best, plan=parse_plan(best) if best else {}, codec=cm.group(1).strip() if cm else None)
        if best:
            return out
    # Material + Codec (vbs/py/sh/mjs/js)
    cm = re.search(r"(?i)\bCodec_?\w*\s*=\s*(?:\"([^\"]*)\"|'([^']*)')", text)
    codec = (cm.group(1) if cm.group(1) is not None else cm.group(2)) if cm else ""
    if not codec:
        cm2 = re.search(r"HUNTRESS-CODEC:([^\r\n]*)", text)
        codec = cm2.group(1).strip() if cm2 else ""
    rep, xf, param = (codec.split("|") + ["", "", ""])[:3]
    cands = []
    mm = re.search(r"(?i)\bMaterial_?\w*\s*=\s*((?:'[^']*')+|(?:\"[^\"]*\")+)", text)
    if mm:  # adjacent quoted chunks ('a''b' in Bash) are concatenated
        cands.append("".join(re.findall(r"'([^']*)'|\"([^\"]*)\"", mm.group(1)) and
                             ["".join(x) for x in re.findall(r"'([^']*)'|\"([^\"]*)\"", mm.group(1))]))
    mm = re.search(r"HUNTRESS-MATERIAL:([^\r\n]*)", text)
    if mm:
        cands.append(mm.group(1).strip())
    arrs = re.findall(r"\[\s*(\d{1,3}(?:\s*,\s*\d{1,3}){10,})\s*\]", text)
    if len(arrs) > 1:  # material split across several arrays joined with concat()
        for perm in itertools.permutations(arrs[:4]):
            cands.append("[" + ",".join(perm) + "]")
    cands += [c for c in literals(text) if c not in cands]
    pkeys, pseqs = set(), []
    for pp in (param, xf):
        if pp and re.fullmatch(r"[0-9a-fA-F]{1,2}(?:[,:;\s]+[0-9a-fA-F]{1,2})*", pp):
            pv = [int(p, 16) for p in re.split(r"[,:;\s]+", pp) if p]
            pkeys |= set(pv)
            if len(pv) > 1:
                pseqs.append(tuple(pv))
    for material in cands:
        if codec and material == codec:
            continue
        rest = text.replace(material, "")
        keys = pkeys | ints_in(rest)
        seqs = pseqs + key_lists(rest)
        name_, k, raw = brute(nums_from(material, rep), keys, seqs)
        if raw:
            out.update(kind="material", codec=codec, rep=rep, xf=xf, raw=raw, xf_found=(name_, k), plan=parse_plan(raw))
            return out
    out.update(codec=codec, rep=rep, xf=xf)
    # PowerShell base64 JSON
    bm = re.search(r"FromBase64String\('([^']+)'\)", text)
    if bm:
        rawb = base64.b64decode(bm.group(1))
        km = re.search(r"-bxor\s+(0x[0-9a-fA-F]+|\d+)", text)
        if km:
            rawb = bytes(v ^ int(km.group(1), 0) for v in rawb)
        if "[Array]::Reverse" in text:
            rawb = rawb[::-1]
        try:
            out.update(kind="ps1", raw=rawb.decode(), plan=json.loads(rawb))
        except Exception:
            out.update(kind="ps1", raw=rawb.decode("latin1"))
        return out
    return out


if __name__ == "__main__":
    import sys, os
    d = sys.argv[1]
    for f in sorted(os.listdir(d)):
        t = open(os.path.join(d, f), encoding="utf-8-sig", errors="replace").read()
        r = decode_specimen(f, t)
        print("==", f, r["kind"], r.get("codec"), r.get("xf_found"), r.get("enc", ""))
        print("   ", (r["raw"] or "<NONE>")[:600])
