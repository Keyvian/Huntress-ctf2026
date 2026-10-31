"""Day-11 binary 'D-Day' solver (d01..d11), any mode. Built on the Day-10 b10.py.
d01 ELF structural; d02 C++ (ELF|PE)+HCFG; d03 .NET pe_cli; d04 Go / d05 Rust (+HCFG ver/xor);
d06 Java jar / d07 Kotlin jar (base64 HCFG in .class); d08 Swift ELF; d09 Nim ELF (base64 'SENG..' literal);
d10 Zig ELF|PE with raw XOR'd HCFG in a dedicated `.hcfg` section;
d11 D (ldc/gdc) binary with a base64 'SENG..' literal in .rodata (same fields as d09, incl. hcfg_offset).
usage: b11.py <challenge> [--dir cached_dir] [--submit] [--only ids] [--set-override k=v,...]"""
import sys, os, io, json, re, time, zlib, struct, hashlib, base64, zipfile
sys.path.insert(0, "~/ctf")
import pyzipper
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
import capstone
import dnfile

cj = lambda x: json.dumps(x, separators=(",", ":"))
sha256 = lambda b: hashlib.sha256(b).hexdigest()


def unzip(data, pwd=b"infected"):
    zf = pyzipper.AESZipFile(io.BytesIO(data))
    zf.setpassword(pwd)
    return [(zi.filename, zf.read(zi.filename)) for zi in zf.infolist() if not zi.filename.endswith("/")]


def hcfg_blocks(b, base_off=0):
    out, p = [], b.find(b"HCFG")
    while p != -1:
        if p + 12 <= len(b):
            ver, key, size = b[p + 4], b[p + 5], struct.unpack("<H", b[p + 6:p + 8])[0]
            plain = bytes(x ^ key for x in b[p + 12:p + 12 + size])
            try:
                obj, end = json.JSONDecoder().raw_decode(plain.decode("utf-8", "strict"))
                if isinstance(obj, dict):
                    pj = plain[:end] if end < len(plain) else plain
                    out.append(dict(off=base_off + p, raw_off=p, ver=ver, key=key, cfg=obj, plain=pj,
                                    crc=zlib.crc32(pj) & 0xffffffff))
            except Exception:
                pass
        p = b.find(b"HCFG", p + 1)
    return out


def b64_hcfg(blob):
    out = []
    for m in re.finditer(rb"SENG[A-Za-z0-9+/]{16,}={0,2}", blob):
        s = m.group(0)
        try:
            for d in hcfg_blocks(base64.b64decode(s + b"=" * (-len(s) % 4))):
                d["b64_off"] = m.start(); d["off"] = m.start()
                out.append(d)
        except Exception:
            pass
    return out


def best(blocks):
    return max(blocks, key=lambda d: (all(k in d["cfg"] for k in ("campaign", "domain", "mutex")), len(d["cfg"])))


def cfg_fields(pfx, blk, url=True, xor=True, ver=False):
    c = blk["cfg"]
    d = {pfx + "analysis_config_campaign": c.get("campaign", "none"),
         pfx + "analysis_config_domain": c.get("domain", "none"),
         pfx + "analysis_config_mutex": c.get("mutex", "none"),
         pfx + "analysis_config_crc32_hex": "0x%08x" % blk["crc"]}
    if url: d[pfx + "analysis_config_url"] = c.get("url", "none")
    if xor: d[pfx + "analysis_xor_key_hex"] = "0x%02x" % blk["key"]
    if ver: d[pfx + "analysis_hcfg_version"] = str(blk["ver"])
    return d


def fmt_of(b):
    if b[:4] == b"\x7fELF": return "elf"
    if b[:2] == b"MZ": return "pe"
    if b[:2] == b"PK": return "jar"
    if b[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe"): return "macho"
    return "unknown"


ELF_ARCH = {62: "x86-64", 3: "i386", 183: "aarch64", 40: "arm"}
PE_ARCH = {0x8664: "x86-64", 0x14c: "i386", 0xaa64: "aarch64", 0x1c0: "arm"}


def arch_of(b):
    if b[:4] == b"\x7fELF":
        return ELF_ARCH.get(struct.unpack("<H", b[18:20])[0], "unknown")
    if b[:2] == b"MZ":
        e = struct.unpack("<I", b[0x3C:0x40])[0]
        return PE_ARCH.get(struct.unpack("<H", b[e + 4:e + 6])[0], "unknown")
    return "unknown"


def machine_int(b):
    if b[:4] == b"\x7fELF":
        return str(struct.unpack("<H", b[18:20])[0])
    if b[:2] == b"MZ":
        e = struct.unpack("<I", b[0x3C:0x40])[0]
        return str(struct.unpack("<H", b[e + 4:e + 6])[0])
    return "none"


def sec_names(b):
    if b[:4] == b"\x7fELF":
        return [s.name for s in ELFFile(io.BytesIO(b)).iter_sections()]
    if b[:2] == b"MZ":
        e = struct.unpack("<I", b[0x3C:0x40])[0]
        n, opt = struct.unpack("<H", b[e + 6:e + 8])[0], struct.unpack("<H", b[e + 20:e + 22])[0]
        o = e + 24 + opt
        return [b[o + 40 * i:o + 40 * i + 8].rstrip(b"\x00").decode("latin-1") for i in range(n)]
    return []


def d01_fields(b):
    elf = ELFFile(io.BytesIO(b))
    h = elf.header
    secs = [s.name for s in elf.iter_sections()]
    st = elf.get_section_by_name(".symtab")
    syms = [s.name for s in st.iter_symbols() if s.name] if isinstance(st, SymbolTableSection) else []
    dis = []
    if isinstance(st, SymbolTableSection):
        rc = [s for s in st.iter_symbols() if s.name == "recover_code" and s["st_info"]["type"] == "STT_FUNC"]
        if rc:
            s = rc[0]; addr, size = s["st_value"], s["st_size"]
            for sec in elf.iter_sections():
                a, sz = sec["sh_addr"], sec["sh_size"]
                if sec["sh_type"] != "SHT_NOBITS" and a <= addr < a + sz:
                    code = sec.data()[addr - a:addr - a + size]
                    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if elf.elfclass == 64 else capstone.CS_MODE_32)
                    for ins in md.disasm(code, addr):
                        ops = re.sub(r"\b0x([0-9a-f]+)\b", lambda m: str(int(m.group(1), 16)), ins.op_str)
                        dis.append((ins.mnemonic + " " + ops).strip())
                    break
    mach = {"EM_X86_64": "x86-64", "EM_386": "i386", "EM_AARCH64": "aarch64"}.get(h["e_machine"], h["e_machine"])
    return {"d01_artifact_sha256_1": sha256(b),
            "d01_analysis_elf_class": "ELF%d" % elf.elfclass,
            "d01_analysis_machine": mach,
            "d01_analysis_section_names": cj(secs),
            "d01_analysis_symbols": cj(syms),
            "d01_analysis_disassembly": cj(dis),
            "d01_analysis_elf_type": h["e_type"],
            "d01_analysis_endianness": "little" if elf.little_endian else "big",
            "d01_analysis_entry_point": "0x%x" % h["e_entry"],
            "d01_analysis_has_symtab": "true" if st is not None else "false"}


def set_answers(files):
    """files: list of (name, bytes) for ONE set. Returns (answers without set prefix, diag)."""
    by = {}
    for n, b in files:
        m = re.match(r"(d\d\d)", os.path.basename(n))
        if m:
            by.setdefault(m.group(1), []).append((n, b))
    A, diag = {}, {}
    if "d01" in by:
        A.update(d01_fields(by["d01"][0][1]))
    if "d02" in by:
        b = by["d02"][0][1]; bl = hcfg_blocks(b) or b64_hcfg(b); diag["d02_hcfg"] = len(bl)
        A["d02_artifact_sha256_1"] = sha256(b); A["d02_analysis_format"] = fmt_of(b)
        if bl: A.update(cfg_fields("d02_", best(bl)))
        A["d02_analysis_has_cpp_typeinfo"] = "true" if b"_ZTI" in b else "false"
        A["d02_analysis_has_cpp_vtable"] = "true" if b"_ZTV" in b else "false"
    if "d03" in by:
        dll = [x for x in by["d03"] if x[0].endswith(".dll") or x[1][:2] == b"MZ"][0][1]
        rcs = [x for x in by["d03"] if x[0].endswith(".json")]
        A["d03_artifact_sha256_1"] = sha256(dll)
        if rcs: A["d03_artifact_sha256_2"] = sha256(rcs[0][1])
        diag["d03_order"] = [x[0] for x in by["d03"]]
        pe = dnfile.dnPE(data=dll)
        A["d03_analysis_format"] = "pe_cli" if pe.net is not None else "pe"
        A["d03_analysis_machine"] = {0x14c: "i386", 0x8664: "x86-64"}.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))
        A["d03_analysis_metadata_version"] = pe.net.metadata.struct.Version.rstrip(b"\x00").decode()
        bl = hcfg_blocks(dll)
        if not bl:
            bl = b64_hcfg(dll) + b64_hcfg(dll.replace(b"\x00", b""))
        diag["d03_hcfg"] = len(bl)
        if bl: A.update(cfg_fields("d03_", best(bl), url=True, xor=False))
    for d in ("d04", "d05"):
        if d in by:
            b = by[d][0][1]; bl = hcfg_blocks(b) or b64_hcfg(b); diag[d + "_hcfg"] = len(bl)
            A[d + "_artifact_sha256_1"] = sha256(b); A[d + "_analysis_format"] = fmt_of(b)
            A[d + "_analysis_architecture"] = arch_of(b)
            if bl: A.update(cfg_fields(d + "_", best(bl), ver=True))
    for d in ("d06", "d07"):
        if d in by:
            b = by[d][0][1]
            A[d + "_artifact_sha256_1"] = sha256(b); A[d + "_analysis_format"] = "jar"
            jz = zipfile.ZipFile(io.BytesIO(b))
            meths = []  # graded format (Day 9 single): numeric ZIP method ids, first-appearance order -> [0,8]
            for zi in jz.infolist():
                if zi.compress_type not in meths: meths.append(zi.compress_type)
            A[d + "_analysis_compression_methods"] = cj(meths)
            bl = []
            top = [zi for zi in jz.infolist() if zi.filename.endswith(".class") and "/" not in zi.filename]
            rest = [zi for zi in jz.infolist() if zi.filename.endswith(".class") and "/" in zi.filename and not zi.filename.startswith("kotlin/")]
            for zi in top + rest:
                bl += b64_hcfg(jz.read(zi))
                if bl: break
            diag[d + "_hcfg"] = len(bl)
            if bl: A.update(cfg_fields(d + "_", best(bl), ver=True))
    if "d08" in by:
        b = by["d08"][0][1]
        A["d08_artifact_sha256_1"] = sha256(b); A["d08_analysis_format"] = fmt_of(b)
        A["d08_analysis_architecture"] = arch_of(b)
        A["d08_analysis_elf_class"] = {1: "32", 2: "64"}.get(b[4], "none") if b[:4] == b"\x7fELF" else "none"  # bits (graded)
        A["d08_analysis_machine"] = machine_int(b)
        bl = hcfg_blocks(b) or b64_hcfg(b); diag["d08_hcfg"] = len(bl)
        if bl: A.update(cfg_fields("d08_", best(bl), xor=False))
    if "d10" in by:
        b = by["d10"][0][1]
        A["d10_artifact_sha256_1"] = sha256(b); A["d10_analysis_format"] = fmt_of(b)
        A["d10_analysis_architecture"] = arch_of(b)
        A["d10_analysis_machine"] = machine_int(b)
        secs = sec_names(b); diag["d10_secs"] = secs
        A["d10_analysis_has_hcfg_section"] = "true" if any(s.lower().strip(".").startswith("hcfg") for s in secs) else "false"
        bl = hcfg_blocks(b) or b64_hcfg(b)
        diag["d10_hcfg"] = [(x["off"], x["cfg"].get("campaign")) for x in bl]
        if bl: A.update(cfg_fields("d10_", best(bl), xor=False))
    for d in ("d09", "d11"):
        if d not in by:
            continue
        b = by[d][0][1]
        A[d + "_artifact_sha256_1"] = sha256(b); A[d + "_analysis_format"] = fmt_of(b)
        A[d + "_analysis_architecture"] = arch_of(b)
        A[d + "_analysis_machine"] = machine_int(b)
        bl = b64_hcfg(b); raw = hcfg_blocks(b)
        diag[d + "_hcfg_b64"] = [(x["off"], x["cfg"].get("campaign")) for x in bl]
        diag[d + "_hcfg_raw"] = [(x["off"], x["cfg"].get("campaign")) for x in raw]
        allb = bl + raw
        if allb:
            bb = best(allb)
            A.update(cfg_fields(d + "_", bb, xor=False))
            A[d + "_analysis_hcfg_offset"] = str(bb["off"])
    return A, diag


def gm_call(f, *a, tries=12):
    """Call a GM op, backing off on rate_limited / empty responses (the 3 parallel agents share a token)."""
    d, r = 0.6, None
    for _ in range(tries):
        try:
            r = f(*a)
        except Exception as e:
            r = {"error": "exc:%s" % e}
        bad = (isinstance(r, dict) and (not r or r.get("error") == "rate_limited")) or \
              (isinstance(r, (bytes, bytearray)) and r.startswith(b'{"error":"rate_limited"'))
        if not bad:
            return r
        time.sleep(d); d = min(d * 1.6, 6)
    return r


def gather(g, ch, nsets, save=None):
    """Return {setno: [(name,bytes)...]} ; set 1 = default delivery, delivery K = set K+1.
    Mastery deliveries are fetched in parallel (one session per thread)."""
    from concurrent.futures import ThreadPoolExecutor
    from gm import GM
    sets = {}

    def add(raw, setno):
        files = unzip(raw)
        inner = [(n, b) for n, b in files if b[:2] == b"PK" and n.endswith(".zip")]
        if inner:
            for i, (n, b) in enumerate(inner):
                m = re.search(r"(\d+)\D*$", n)
                add(b, int(m.group(1)) if m else i + 1)
        else:
            sets.setdefault(setno, []).extend(files)

    def fetch(d):
        r = gm_call((g if d is None else GM()).artifact, ch, d)
        if save:
            open(os.path.join(save, "artifact%s.bin" % ("" if d is None else "_d%d" % d)), "wb").write(r)
        return d, r
    dels = [None] + (list(range(1, nsets)) if nsets > 1 else [])
    with ThreadPoolExecutor(len(dels)) as ex:
        raws = list(ex.map(fetch, dels))
    add(raws[0][1], 1)
    if len(sets) < nsets:
        for d, r in raws[1:]:
            if r[:2] == b"PK":
                add(r, d + 1)
    return sets


if __name__ == "__main__":
    ch = sys.argv[1]
    t0 = time.time()
    if "--dir" in sys.argv:
        dd = sys.argv[sys.argv.index("--dir") + 1]
        st = json.load(open(os.path.join(dd, "start.json")))
        sets = {}
        for f in sorted(os.listdir(dd)):
            m = re.fullmatch(r"artifact(?:_d(\d+))?\.bin", f)
            if m:  # default delivery = set1, delivery K = set K+1 (0-based deliveries)
                k = int(m.group(1)) + 1 if m.group(1) else 1
                if k in sets and m.group(1) == "0":
                    continue
                sets[k] = unzip(open(os.path.join(dd, f), "rb").read())
    else:
        from gm import GM
        g = GM()
        op = "practice" if "--practice" in sys.argv else ("retry" if "--retry" in sys.argv else "start")
        st = gm_call(getattr(g, op), ch)
        save = sys.argv[sys.argv.index("--save") + 1] if "--save" in sys.argv else None
        if save:
            os.makedirs(save, exist_ok=True)
            json.dump(st, open(os.path.join(save, "start.json"), "w"), indent=1, ensure_ascii=False)
        print("OP", op, {k: st.get(k) for k in ("attempt_id", "mode", "started_at", "deadline", "error",
                                                 "unique_attempts_remaining")}, "n_aids", len(st.get("answer_ids") or []))
        if not st.get("answer_ids"):
            print("NO LIVE ATTEMPT", json.dumps({k: v for k, v in st.items() if k not in ("questions", "guidance")})[:800])
            sys.exit(2)
        aids0 = st.get("answer_ids") or []
        nsets = len({a.split(".")[0] for a in aids0 if a.startswith("set")}) or 1
        sets = gather(g, ch, nsets, save)
        print("gathered sets", sorted(sets), "t=%.1fs" % (time.time() - t0))
    aids = st.get("answer_ids") or [q["id"] for q in st["questions"]]
    ans = {}
    for k in sorted(sets):
        A, diag = set_answers(sets[k])
        print("SET", k, "files", [n for n, _ in sets[k]], "diag", diag)
        for a, v in A.items():
            ans[a if not any(x.startswith("set") for x in aids) else "set%d.%s" % (k, a)] = v
    miss = [a for a in aids if a not in ans]
    print("computed", len([a for a in aids if a in ans]), "/", len(aids), "missing", miss[:30], "t=%.1fs" % (time.time() - t0))
    if "--show" in sys.argv:
        for a in aids:
            v = ans.get(a, "<MISSING>")
            print("  %-48s %s" % (a, v if len(v) < 140 else v[:137] + "..."))
    if "--set-override" in sys.argv:
        for kv in sys.argv[sys.argv.index("--set-override") + 1].split(","):
            k, v = kv.split("=", 1); ans[k] = v
    if "--submit" in sys.argv:
        from gm import GM
        sub = {a: ans[a] for a in aids if a in ans}
        if "--only" in sys.argv:
            ids = sys.argv[sys.argv.index("--only") + 1].split(",")
            sub = {k: v for k, v in sub.items() if any(re.search(i, k) for i in ids)}
        if "--exclude" in sys.argv:
            ids = sys.argv[sys.argv.index("--exclude") + 1].split(",")
            sub = {k: v for k, v in sub.items() if not any(re.search(i, k) for i in ids)}
        r = gm_call(GM().submit, ch, sub)
        print("SUBMIT", len(sub), {k: r.get(k) for k in ("result", "flag", "error", "remaining")},
              "t=%.1fs" % (time.time() - t0))
        if r.get("result") not in ("CORRECT", "accepted", "already_solved") and "--split-on-fail" in sys.argv:
            # bank per (set, dNN) group to isolate the wrong field group(s)
            groups = {}
            for k, v in sub.items():
                m = re.match(r"((?:set\d+\.)?d\d\d)_", k)
                groups.setdefault(m.group(1) if m else k, {})[k] = v
            gg = GM()
            for gk, gs in groups.items():
                rr = gm_call(gg.submit, ch, gs)
                print("  GROUP", gk, len(gs), {k: rr.get(k) for k in ("result", "flag", "error", "remaining")})
                if rr.get("flag"):
                    break
                time.sleep(0.3)
