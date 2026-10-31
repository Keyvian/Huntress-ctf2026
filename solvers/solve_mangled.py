#!/usr/bin/env python3
import sys, os, re, json, io, tempfile, subprocess, struct, hashlib, zlib, time
import requests, pyzipper
GM = "http://<homebase-ip>/huntress-ctf-proxy"
S = requests.Session(); S.headers.update({"Content-Type": "application/json"})
PW = b"infected"
MACH = {62:"x86-64",3:"i386",40:"arm",183:"aarch64"}


def run(*a):
    return subprocess.run(a, capture_output=True, text=True, errors="replace").stdout


def unzip_aes(data):
    z = pyzipper.AESZipFile(io.BytesIO(data)); z.setpassword(PW)
    out = {}
    for n in z.namelist():
        try:
            out[n] = z.read(n)
        except Exception:
            pass
    return out


def c_facts(path, data):
    f = {}
    f["c_sha256"] = hashlib.sha256(data).hexdigest()
    with open(path, "rb") as fh: b = fh.read()
    e_machine = struct.unpack_from("<H", b, 18)[0]
    f["c_machine"] = MACH.get(e_machine, "0x%x" % e_machine)
    rs = run("readelf", "-S", "-W", path)
    f["c_has_symtab"] = "true" if re.search(r"\.symtab\b", rs) else "false"
    f["c_marker"] = "none"
    hx = run("readelf", "-x", ".huntress", path)
    if "Hex dump" in hx:
        raw = bytearray()
        for line in hx.splitlines():
            m = re.match(r"\s*0x[0-9a-fA-F]+\s+((?:[0-9a-fA-F]{2,8}\s){1,4})", line)
            if m:
                for tok in m.group(1).split():
                    for i in range(0, len(tok), 2): raw.append(int(tok[i:i+2], 16))
        f["c_marker"] = bytes(raw).split(b"\x00")[0].decode("utf-8", "replace")
    f["c_recover_code"] = "none"
    dis = run("objdump", "-d", "-M", "intel", path)
    mm = re.search(r"<recover_code>:(.*?)(?:\n\n|\Z)", dis, re.S)
    if mm:
        m2 = re.search(r"mov\s+eax,0x([0-9a-fA-F]+)", mm.group(1))
        if m2: f["c_recover_code"] = str(int(m2.group(1), 16))
    return f


def read_section(path, name):
    b = open(path, "rb").read()
    secs = run("readelf", "-SW", path)
    for m in re.finditer(r"\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)", secs):
        nm, addr, off, size = m.group(1), int(m.group(2), 16), int(m.group(3), 16), int(m.group(4), 16)
        if nm == name:
            return b[off:off+size]
    return b""


def find_config(data):
    """Format-agnostic: locate the XOR-encoded HCFG config blob, return (key, json_bytes)."""
    starts = [m.start() for m in re.finditer(b"HCFG", data)] or [0]
    for idx in starts:
        region = data[idx: idx + 2048]
        for k in range(1, 256):
            dec = bytes(x ^ k for x in region)
            if b'"campaign"' in dec and b'"domain"' in dec:
                s = dec.find(b"{")
                depth = 0; end = None
                for i in range(s, len(dec)):
                    if dec[i] == 0x7b: depth += 1
                    elif dec[i] == 0x7d:
                        depth -= 1
                        if depth == 0: end = i + 1; break
                if end:
                    return k, dec[s:end]
    return None, None


def cpp_facts(path, data):
    f = {}
    f["cpp_sha256"] = hashlib.sha256(data).hexdigest()
    f["cpp_format"] = "elf" if data[:4] == b"\x7fELF" else ("pe" if data[:2] == b"MZ" else "unknown")
    syms = []
    for line in run("nm", path).splitlines():
        p = line.split()
        if p: syms.append(p[-1])
    data_syms = syms + [s.decode() for s in re.findall(rb"[.\w$]*_Z[A-Za-z0-9_$]+", data)]

    def is_user(s):
        return "cxxabiv" not in s and "St9type_info" not in s and "_ZTVN" not in s

    def pick(cands, prefer):
        cands = [c for c in cands if is_user(c)]
        for c in cands:
            if c.startswith(prefer): return c
        for c in cands:
            if "$" not in c: return c      # bare (ELF)
        return cands[0] if cands else "none"

    vt_cands = [s for s in data_syms if "_ZTV" in s and is_user(s)]
    ti_cands = [s for s in data_syms if "_ZTI" in s and is_user(s)]
    sc_cands = [s for s in data_syms if re.search(r"_Z.*[sS]core", s)]
    f["has_cpp_vtable"] = "true" if vt_cands else "false"
    f["has_cpp_typeinfo"] = "true" if ti_cands else "false"
    f["vtable_symbol"] = pick(vt_cands, ".rdata$")
    f["mangled_score_symbol"] = pick(sc_cands, ".text$")
    key, js = find_config(data)
    f["cpp_xor_key"] = "0x%x" % key if key is not None else "none"
    cfg = {}
    if js:
        try: cfg = json.loads(js.decode("utf-8", "replace"))
        except Exception: cfg = {}
    for fld in ("campaign", "domain", "url", "mutex"):
        f[fld] = cfg.get(fld, "none")
    f["cpp_config_crc32"] = "0x%08x" % (zlib.crc32(js) & 0xffffffff) if js else "none"
    return f


def extract_facts(cid, delivery=None):
    params = {"op": "artifact", "challenge": cid}
    if delivery is not None:
        params["delivery"] = delivery
    data = S.get(GM, params=params).content
    if data[:1] == b"{" and b"error" in data[:60]:
        data = S.get(GM, params={"op": "artifact", "challenge": cid}).content
    members = unzip_aes(data)
    tmpd = tempfile.mkdtemp()
    cfile = cppfile = None; cbytes = cppbytes = None
    for n, d in members.items():
        p = os.path.join(tmpd, re.sub(r"[^A-Za-z0-9._-]", "_", n))
        open(p, "wb").write(d)
        if b"_ZTV" in run("nm", p).encode() or "cpp" in n.lower() or b"_ZN" in d:
            cppfile, cppbytes = p, d
        else:
            cfile, cbytes = p, d
    if cfile is None and len(members) == 2:  # fallback by name
        pass
    facts = {}
    if cfile: facts.update(c_facts(cfile, cbytes))
    if cppfile: facts.update(cpp_facts(cppfile, cppbytes))
    return facts


def main():
    cid = sys.argv[1]
    st = S.post(GM, data=json.dumps({"op": "start", "challenge": cid})).json()
    if st.get("answer_ids") is None or st.get("error"):
        st = S.post(GM, data=json.dumps({"op": "retry", "challenge": cid})).json()
    aids = st.get("answer_ids") or []
    print("mode=%s deadline=%s n=%d" % (st.get("mode"), st.get("deadline"), len(aids)))
    sets = sorted({int(m.group(1)) for a in aids for m in [re.match(r"set(\d+)\.", a)] if m})
    answers = {}
    if sets:
        for s in sets:
            facts = extract_facts(cid, delivery=s - 1)
            for a in aids:
                m = re.match(r"set%d\.(.+)$" % s, a)
                if m and m.group(1) in facts:
                    answers[a] = facts[m.group(1)]
    else:
        facts = extract_facts(cid)
        for k in sorted(facts): print("  %s = %r" % (k, facts[k]))
        answers = {a: facts[a] for a in aids if a in facts}
    print("computed %d/%d" % (len(answers), len(aids)))
    r = S.post(GM, data=json.dumps({"op": "submit", "challenge": cid, "answers": answers})).json()
    print("SUBMIT:", json.dumps({k: r.get(k) for k in ("result", "flag", "remaining", "status", "error")}))
    if r.get("result") not in ("CORRECT", "already_solved"):
        # individual fallback: lock correct answers, reveal wrong ones
        bad = []; last = r
        for a, v in answers.items():
            rr = S.post(GM, data=json.dumps({"op": "submit", "challenge": cid, "answers": {a: v}})).json()
            last = rr
            if rr.get("result") == "incorrect": bad.append((a, v))
            if rr.get("result") == "CORRECT":
                print("FLAG:", rr.get("flag")); return
        print("final remaining=%s result=%s" % (last.get("remaining"), last.get("result")))
        print("bad:", bad)


if __name__ == "__main__":
    main()
