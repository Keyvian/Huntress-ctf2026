"""Day-9 metadata 'Built Different' solver (any mode).
Questions are 'Determine <field> for <file>.' (+ the evidence-note hash block). Field values computed from the
real decompressed member bytes. usage: m9.py <challenge> [--dir cached_start_dir] [--submit] [--only id1,id2]"""
import sys, os, io, json, re, struct, hashlib, zipfile
sys.path.insert(0, "~/ctf")
from gm import GM
try:
    import pyzipper
except Exception:
    pyzipper = None

cj = lambda x: json.dumps(x, separators=(",", ":"))


def unzip_all(data, pfx=""):
    """Recursively flatten zips -> list of (path, bytes). Inner zips are kept AND expanded."""
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
        if b[:4] == b"PK\x03\x04" and re.search(r"(evidence|set|bundle|delivery)", zi.filename, re.I) and not re.search(r"drop", zi.filename, re.I):
            out += unzip_all(b, p + "/")
    return out


# ------------------------------------------------------------------ field extractors
def jpeg_sof(b):
    i = 2
    while i + 4 <= len(b):
        if b[i] != 0xFF:
            i += 1; continue
        m = b[i + 1]
        if m in (0xD8, 0x01, 0xFF) or 0xD0 <= m <= 0xD7:
            i += 1 if m == 0xFF else 2; continue
        ln = struct.unpack(">H", b[i + 2:i + 4])[0]
        if 0xC0 <= m <= 0xCF and m not in (0xC4, 0xC8, 0xCC):
            h, w = struct.unpack(">HH", b[i + 5:i + 9]); return "%dx%d" % (w, h)
        i += 2 + ln
    return "none"


def png_ihdr(b):
    if b[:8] != b"\x89PNG\r\n\x1a\n" or b[12:16] != b"IHDR":
        return "none"
    w, h = struct.unpack(">II", b[16:24]); return "%dx%d" % (w, h)


def pdf_ver(b):
    m = re.search(rb"%PDF-(\d+\.\d+)", b[:1024]); return m.group(1).decode() if m else "none"


def zip_eocd_total(b):
    e = b.rfind(b"PK\x05\x06")
    return str(struct.unpack("<H", b[e + 10:e + 12])[0]) if e >= 0 else "none"


def zip_cd_names(b):
    e = b.rfind(b"PK\x05\x06")
    if e < 0:
        return "none"
    n, cdsz, cdoff = struct.unpack("<HII", b[e + 10:e + 20])
    names, p = [], cdoff
    for _ in range(n):
        if b[p:p + 4] != b"PK\x01\x02":
            break
        fl, el, cl = struct.unpack("<HHH", b[p + 28:p + 34])
        names.append(b[p + 46:p + 46 + fl].decode("utf-8", "replace"))
        p += 46 + fl + el + cl
    return cj(names)


def pe_hdr(b):
    if b[:2] != b"MZ" or len(b) < 0x40:
        return None
    e = struct.unpack("<I", b[0x3C:0x40])[0]
    if b[e:e + 4] != b"PE\x00\x00":
        return None
    mach, nsec, ts, _, _, opt_sz, chars = struct.unpack("<HHIIIHH", b[e + 4:e + 24])
    magic = struct.unpack("<H", b[e + 24:e + 26])[0] if opt_sz >= 2 else 0
    return dict(off=e, machine=mach, nsec=nsec, ts=ts, opt_sz=opt_sz, chars=chars, magic=magic)


def elf_hdr(b):
    if b[:4] != b"\x7fELF":
        return None
    cls, data = b[4], b[5]
    en = "<" if data == 1 else ">"
    et, em = struct.unpack(en + "HH", b[16:20])
    return dict(cls=cls, data=data, osabi=b[7], type=et, machine=em)


MACHO_MAGICS = {b"\xfe\xed\xfa\xce": (">", 32), b"\xce\xfa\xed\xfe": ("<", 32),
                b"\xfe\xed\xfa\xcf": (">", 64), b"\xcf\xfa\xed\xfe": ("<", 64)}


def macho_hdr(b):
    if b[:4] in MACHO_MAGICS:
        en, bits = MACHO_MAGICS[b[:4]]
        ct, cst, ft, ncmds = struct.unpack(en + "iIII", b[4:20])
        return dict(en=en, bits=bits, cputype=ct & 0xffffffff, cpusubtype=cst, filetype=ft, ncmds=ncmds, fat=False)
    if b[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
        n = struct.unpack(">I", b[4:8])[0]
        if 0 < n < 30:
            arches = []
            for i in range(n):
                ct, cst = struct.unpack(">iI", b[8 + 20 * i:16 + 20 * i])
                arches.append(ct & 0xffffffff)
            return dict(fat=True, nfat=n, arches=arches)
    return None


def text_bom(b):
    return "true" if b.startswith(b"\xef\xbb\xbf") else "false"


FIELDS = {
    "text.utf8_bom_present": text_bom,
    "jpeg.sof_dimensions_pixels": jpeg_sof,
    "png.ihdr_dimensions_pixels": png_ihdr,
    "pdf.header_version": pdf_ver,
    "zip.eocd_total_entries": zip_eocd_total,
    "zip.central_directory_member_names": zip_cd_names,
    "pe.coff_machine_u16_hex": lambda b: ("0x%04x" % pe_hdr(b)["machine"]) if pe_hdr(b) else "none",
}


def find_member(files, art, setno):
    """art e.g. 'metadata-day-09-evidence.zip -> camera-001.jpg'; files list of (path,bytes)."""
    base = art.split("->")[-1].strip()
    hits = [(p, b) for p, b in files if os.path.basename(p) == base]
    cont = art.split("->")[0].strip() if "->" in art else None
    if cont and len(hits) > 1:
        ch = [(p, b) for p, b in hits if cont in p.split("/")]
        if len(ch) == 1:
            return ch[0]
    if setno is not None and len(hits) > 1:
        sh = [(p, b) for p, b in hits if re.search(r"(?:set|bundle)[-_]?0*%d\b" % setno, p, re.I)]
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
        if sid == "evidence-note-filename" or sid.endswith("-filename") and "Determine" not in text:
            # 'first evidence note' -> look for the member named in sibling questions
            sib = [x.get("artifact", "") for x in st["questions"] if x["id"].startswith(qid.rsplit("filename", 1)[0]) and "->" in x.get("artifact", "")]
            ans[qid] = sib[0].split("->")[-1].strip() if sib else "evidence-note.txt"
            continue
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
        elif re.search(r"-magic-prefix-hex-(\d+)$", sid):
            n = int(re.search(r"-magic-prefix-hex-(\d+)$", sid).group(1)); ans[qid] = b[:n].hex()
        elif re.search(r"-magic-suffix-hex-(\d+)$|-last-(\d+)", sid):
            mm = re.search(r"-(?:magic-suffix-hex|last)-(\d+)", sid); ans[qid] = b[-int(mm.group(1)):].hex()
        else:
            fm = re.search(r"Determine ([\w.]+) for", text)
            fld = fm.group(1) if fm else None
            if fld in FIELDS:
                ans[qid] = FIELDS[fld](b)
            else:
                unk.append((qid, fld, p, len(b), b[:8].hex()))
    return ans, unk


if __name__ == "__main__":
    ch = sys.argv[1]
    if "--dir" in sys.argv:
        dd = sys.argv[sys.argv.index("--dir") + 1]
        st = json.load(open(os.path.join(dd, "start.json")))
        raws = [open(os.path.join(dd, f), "rb").read() for f in sorted(os.listdir(dd)) if f.startswith("artifact")]
    else:
        g = GM(); st = g.start(ch); raws = [g.artifact(ch)]
    files = []
    for r in raws:
        files += unzip_all(r)
    ans, unk = solve(st, files)
    for k, v in ans.items():
        print("  %-60s %s" % (k, v if len(v) < 150 else v[:147] + "..."))
    print("UNKNOWN", len(unk))
    for u in unk:
        print("  ", u)
    if "--submit" in sys.argv:
        sub = ans
        if "--only" in sys.argv:
            ids = sys.argv[sys.argv.index("--only") + 1].split(",")
            sub = {k: v for k, v in ans.items() if any(k == i or k.endswith(i) for i in ids)}
        r = GM().submit(ch, sub)
        print("SUBMIT", len(sub), {k: r.get(k) for k in ("result", "flag", "error", "remaining")})
