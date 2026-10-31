"""Day-10 metadata 'Where Do We Begin?' solver (any mode).
usage: m10.py <challenge> [start|retry|practice|none] [--submit] [--dir cached] [--save outdir]
Questions are 'Determine <field> for <file>.'; values computed from real decompressed member bytes."""
import sys, os, io, json, re, struct, hashlib, zipfile, time
sys.path.insert(0, "~/ctf")
from gm import GM
try:
    import pyzipper
except Exception:
    pyzipper = None

cj = lambda x: json.dumps(x, separators=(",", ":"))


def unzip_all(data, pfx=""):
    out = []
    try:
        if pyzipper:
            zf = pyzipper.AESZipFile(io.BytesIO(data)); zf.setpassword(b"infected")
        else:
            zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()
    except Exception:
        return out
    for zi in infos:
        if zi.filename.endswith("/"):
            continue
        b = zf.read(zi.filename)
        p = pfx + zi.filename
        out.append((p, b))
        if b[:4] == b"PK\x03\x04" and zi.filename.lower().endswith(".zip"):
            out += unzip_all(b, p + "/")
    return out


# ------------------------------------------------------------------ headers
def pe_info(b):
    if b[:2] != b"MZ" or len(b) < 0x40:
        return None
    e = struct.unpack("<I", b[0x3C:0x40])[0]
    if b[e:e + 4] != b"PE\x00\x00":
        return None
    mach, nsec, ts, _, _, opt_sz, chars = struct.unpack("<HHIIIHH", b[e + 4:e + 24])
    o = e + 24
    magic = struct.unpack("<H", b[o:o + 2])[0]
    aep = struct.unpack("<I", b[o + 16:o + 20])[0]
    if magic == 0x20b:
        base = struct.unpack("<Q", b[o + 24:o + 32])[0]
    else:
        base = struct.unpack("<I", b[o + 28:o + 32])[0]
    subsys = struct.unpack("<H", b[o + 68:o + 70])[0]
    secs = []
    so = o + opt_sz
    for i in range(nsec):
        s = b[so + 40 * i: so + 40 * i + 40]
        nm = s[:8].rstrip(b"\x00").decode("latin1")
        vsz, va, rsz, rptr = struct.unpack("<IIII", s[8:24])
        ch = struct.unpack("<I", s[36:40])[0]
        secs.append(dict(name=nm, va=va, vsz=vsz, rsz=rsz, rptr=rptr, ch=ch))
    return dict(off=e, machine=mach, nsec=nsec, ts=ts, opt_sz=opt_sz, chars=chars, magic=magic,
                aep=aep, base=base, subsys=subsys, secs=secs)


def pe_entry_section(pi):
    for s in pi["secs"]:
        if s["va"] <= pi["aep"] < s["va"] + max(s["vsz"], s["rsz"]):
            return s
    return None


def elf_info(b):
    if b[:4] != b"\x7fELF":
        return None
    cls, data = b[4], b[5]
    en = "<" if data == 1 else ">"
    et, em, ev = struct.unpack(en + "HHI", b[16:24])
    if cls == 2:
        entry, phoff, shoff = struct.unpack(en + "QQQ", b[24:48])
    else:
        entry, phoff, shoff = struct.unpack(en + "III", b[24:36])
    return dict(cls=cls, data=data, osabi=b[7], type=et, machine=em, entry=entry)


MACHO_MAGICS = {b"\xfe\xed\xfa\xce": (">", 32), b"\xce\xfa\xed\xfe": ("<", 32),
                b"\xfe\xed\xfa\xcf": (">", 64), b"\xcf\xfa\xed\xfe": ("<", 64)}


def macho_info(b):
    if b[:4] not in MACHO_MAGICS:
        return None
    en, bits = MACHO_MAGICS[b[:4]]
    ct, cst, ft, ncmds, sz = struct.unpack(en + "iIIII", b[4:24])
    p = 28 if bits == 32 else 32
    entryoff = None; text_vmaddr = None; unix_pc = None
    for _ in range(ncmds):
        cmd, csz = struct.unpack(en + "II", b[p:p + 8])
        if cmd == 0x80000028:  # LC_MAIN
            entryoff = struct.unpack(en + "Q", b[p + 8:p + 16])[0]
        elif cmd in (0x19, 0x1):
            segname = b[p + 8:p + 24].rstrip(b"\x00")
            if segname == b"__TEXT":
                text_vmaddr = struct.unpack(en + ("Q" if cmd == 0x19 else "I"), b[p + 24:p + (32 if cmd == 0x19 else 28)])[0]
        p += csz
    return dict(bits=bits, cputype=ct & 0xffffffff, filetype=ft, ncmds=ncmds, entryoff=entryoff, text_vmaddr=text_vmaddr)


PE_MACH = {0x14c: "i386", 0x8664: "amd64", 0xaa64: "arm64", 0x1c0: "arm", 0x1c4: "armnt", 0x200: "ia64"}
ELF_MACH = {3: "x86", 62: "x86-64", 183: "aarch64", 40: "arm", 8: "mips", 243: "riscv"}


def h8(v): return "0x%08x" % v
def h16(v): return "0x%016x" % v


FIELDS = {
    "pe.address_of_entry_point_rva_hex": lambda b: h8(pe_info(b)["aep"]),
    "pe.coff_machine_u16_hex": lambda b: "0x%04x" % pe_info(b)["machine"],
    "pe.image_base_hex": lambda b: (h16 if pe_info(b)["magic"] == 0x20b else h8)(pe_info(b)["base"]),
    "pe.optional_header_magic_u16_hex": lambda b: "0x%04x" % pe_info(b)["magic"],
    "pe.entry_point_section_name": lambda b: (pe_entry_section(pe_info(b)) or {}).get("name", "none"),
    "pe.entry_point_va_hex": lambda b: (h16 if pe_info(b)["magic"] == 0x20b else h8)(pe_info(b)["base"] + pe_info(b)["aep"]),
}


def find_member(files, art, setno):
    base = art.split("->")[-1].strip()
    hits = [(p, b) for p, b in files if os.path.basename(p) == base]
    cont = art.split("->")[0].strip() if "->" in art else None
    if cont and len(hits) > 1:
        ch = [(p, b) for p, b in hits if cont in p.split("/")]
        if len(ch) == 1:
            return ch[0]
    if setno is not None and len(hits) > 1:
        sh = [(p, b) for p, b in hits if re.search(r"(?:set|bundle|evidence)[-_]?0*%d\b" % setno, p, re.I)]
        if sh:
            return sh[0]
        return hits[min(setno - 1, len(hits) - 1)]
    return hits[0] if hits else (None, None)


def solve(st, files):
    ans, unk = {}, []
    for q in st["questions"]:
        qid, text, art = q["id"], q["question"], q.get("artifact") or ""
        m = re.match(r"set(\d+)\.", qid)
        setno = int(m.group(1)) if m else None
        sid = qid.split(".", 1)[1] if m else qid
        p, b = find_member(files, art, setno)
        if b is None:
            unk.append((qid, "NOFILE " + art)); continue
        if sid.endswith("-size-bytes"):
            ans[qid] = str(len(b))
        elif sid.endswith("-md5"):
            ans[qid] = hashlib.md5(b).hexdigest()
        elif sid.endswith("-sha1"):
            ans[qid] = hashlib.sha1(b).hexdigest()
        elif sid.endswith("-sha256"):
            ans[qid] = hashlib.sha256(b).hexdigest()
        else:
            fm = re.search(r"Determine ([\w.]+) for", text)
            fld = fm.group(1) if fm else None
            if fld in FIELDS:
                try:
                    ans[qid] = FIELDS[fld](b)
                except Exception as ex:
                    unk.append((qid, fld, "ERR", repr(ex)))
            else:
                unk.append((qid, fld, p, len(b), b[:8].hex(), text))
    return ans, unk


if __name__ == "__main__":
    ch = sys.argv[1]
    op = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith("--") else "start"
    t0 = time.time()
    g = GM()
    if "--dir" in sys.argv:
        dd = sys.argv[sys.argv.index("--dir") + 1]
        st = json.load(open([os.path.join(dd, f) for f in os.listdir(dd) if f.startswith("start")][0]))
        raws = [open(os.path.join(dd, f), "rb").read() for f in sorted(os.listdir(dd)) if f.startswith("artifact")]
    else:
        st = g.post({"op": op, "challenge": ch}) if op != "none" else g.status(ch)
        if not st.get("answer_ids"):
            print("NO ATTEMPT", {k: v for k, v in st.items() if k != "guidance"}); sys.exit(1)
        raws = [g.artifact(ch)]
        if "--save" in sys.argv:
            sd = sys.argv[sys.argv.index("--save") + 1]; os.makedirs(sd, exist_ok=True)
            json.dump(st, open(os.path.join(sd, "start.json"), "w"))
            open(os.path.join(sd, "artifact.bin"), "wb").write(raws[0])
    print("mode", st.get("mode"), "deadline", st.get("deadline"), "uar", st.get("unique_attempts_remaining"), "nq", len(st["questions"]))
    files = []
    for r in raws:
        files += unzip_all(r)
    ans, unk = solve(st, files)
    print("computed %d/%d in %.2fs; unknown %d" % (len(ans), len(st.get("answer_ids") or []), time.time() - t0, len(unk)))
    if "--submit" in sys.argv and ans:
        sub = ans
        r = g.submit(ch, sub)
        print("SUBMIT", len(sub), {k: r.get(k) for k in ("result", "flag", "error", "remaining")}, "%.2fs" % (time.time() - t0))
    for k, v in list(ans.items())[:400]:
        print("  %-70s %s" % (k, v if len(v) < 150 else v[:147] + "..."))
    for u in unk:
        print("  UNK", u)
