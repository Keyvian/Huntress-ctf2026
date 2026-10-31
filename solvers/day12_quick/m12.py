"""Day-12 metadata 'Managed Expectations' solver (any mode). Superset of m11 (PE header + VS_VERSIONINFO fields) +
.NET metadata fields (dotnet.mvid_guid = Module MVID from #GUID heap, bytes_le canonical lowercase; assembly name/version).
usage: m12.py <challenge> [start|retry|practice|none] [--submit] [--dir cached] [--save outdir]"""
import sys, os, io, json, re, struct, hashlib, zipfile, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import pyzipper
except Exception:
    pyzipper = None
import pefile


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
        if b[:4] == b"PK\x03\x04":
            out += unzip_all(b, p + "/")
    return out


# ------------------------------------------------------------------ version resource
_VCACHE = {}


def version_strings(b):
    """StringFileInfo key -> value (first string table that has the key)."""
    k = hashlib.sha1(b).digest()
    if k in _VCACHE:
        return _VCACHE[k]
    out = {}
    pe = pefile.PE(data=b, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
    for fi in getattr(pe, "FileInfo", []) or []:
        for e in fi:
            for t in getattr(e, "StringTable", []) or []:
                for kk, vv in t.entries.items():
                    kk = kk.decode("utf-8", "replace") if isinstance(kk, bytes) else kk
                    vv = vv.decode("utf-8", "replace") if isinstance(vv, bytes) else vv
                    out.setdefault(kk, vv)
    fixed = (getattr(pe, "VS_FIXEDFILEINFO", None) or [None])[0]
    if fixed is not None:
        out["__fixed_file_version"] = "%d.%d.%d.%d" % (fixed.FileVersionMS >> 16, fixed.FileVersionMS & 0xffff,
                                                       fixed.FileVersionLS >> 16, fixed.FileVersionLS & 0xffff)
        out["__fixed_product_version"] = "%d.%d.%d.%d" % (fixed.ProductVersionMS >> 16, fixed.ProductVersionMS & 0xffff,
                                                          fixed.ProductVersionLS >> 16, fixed.ProductVersionLS & 0xffff)
    _VCACHE[k] = out
    return out


def version_field(b, snake):
    vs = version_strings(b)
    want = snake.replace("_", "").lower()
    for k, v in vs.items():
        if k.replace("_", "").lower() == want:
            return v
    raise KeyError("no version key for %s (have %s)" % (snake, list(vs)))


# ------------------------------------------------------------------ headers (from m10)
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
    base = struct.unpack("<Q", b[o + 24:o + 32])[0] if magic == 0x20b else struct.unpack("<I", b[o + 28:o + 32])[0]
    subsys = struct.unpack("<H", b[o + 68:o + 70])[0]
    secs = []
    so = o + opt_sz
    for i in range(nsec):
        s = b[so + 40 * i: so + 40 * i + 40]
        nm = s[:8].rstrip(b"\x00").decode("latin1")
        vsz, va, rsz, rptr = struct.unpack("<IIII", s[8:24])
        secs.append(dict(name=nm, va=va, vsz=vsz, rsz=rsz, rptr=rptr, ch=struct.unpack("<I", s[36:40])[0]))
    return dict(off=e, machine=mach, nsec=nsec, ts=ts, opt_sz=opt_sz, chars=chars, magic=magic,
                aep=aep, base=base, subsys=subsys, secs=secs)


def pe_entry_section(pi):
    for s in pi["secs"]:
        if s["va"] <= pi["aep"] < s["va"] + max(s["vsz"], s["rsz"]):
            return s
    return None


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


# ------------------------------------------------------------------ .NET metadata (day 12)
_DCACHE = {}


def dotnet_info(b):
    k = hashlib.sha1(b).digest()
    if k in _DCACHE:
        return _DCACHE[k]
    import dnfile, uuid
    pe = dnfile.dnPE(data=b)
    md = pe.net.mdtables
    m = md.Module.rows[0]
    gh = pe.net.metadata.streams.get(b"#GUID")
    raw = gh.__data__ if gh is not None else b""
    mi = getattr(m.struct, "Mvid_GuidIndex", None)
    # MVID: 1-based index into the #GUID heap, 16 bytes each, .NET mixed-endian (bytes_le)
    mvid = str(m.Mvid)
    if isinstance(mi, int) and mi > 0 and len(raw) >= 16 * mi:
        mvid = str(uuid.UUID(bytes_le=bytes(raw[16 * (mi - 1):16 * mi])))
    d = {"mvid_guid": mvid.lower(), "module_name": str(m.Name)}
    if md.Assembly and md.Assembly.rows:
        a = md.Assembly.rows[0]
        d["assembly_name"] = str(a.Name)
        d["assembly_version"] = "%d.%d.%d.%d" % (a.MajorVersion, a.MinorVersion, a.BuildNumber, a.RevisionNumber)
        d["assembly_culture"] = str(a.Culture or "")
    _DCACHE[k] = d
    return d


def field_value(fld, b):
    if fld in FIELDS:
        return FIELDS[fld](b)
    m = re.fullmatch(r"dotnet\.(\w+)", fld or "")
    if m:
        return dotnet_info(b)[m.group(1)]
    m = re.fullmatch(r"pe\.version_(\w+)", fld or "")
    if m:
        return version_field(b, m.group(1))
    raise KeyError("unknown field %s" % fld)


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
        setno = int(m.group(1)) if m else q.get("set")
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
            try:
                ans[qid] = field_value(fld, b)
            except Exception as ex:
                unk.append((qid, fld, p, len(b), b[:8].hex(), text, repr(ex)))
    return ans, unk


def map_ids(st, ans):
    """question ids -> answer_ids (mastery may prefix setN.)."""
    ids = st.get("answer_ids") or []
    out = {}
    for q in st["questions"]:
        if q["id"] not in ans:
            continue
        if q["id"] in ids:
            out[q["id"]] = ans[q["id"]]
        else:
            s = q.get("set")
            for c in ("set%s.%s" % (s, q["id"]), "%s.%s" % (s, q["id"])):
                if c in ids:
                    out[c] = ans[q["id"]]
    return out


if __name__ == "__main__":
    from gmx import GMX
    ch = sys.argv[1]
    op = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith("--") else "start"
    t0 = time.time()
    g = GMX()
    if "--dir" in sys.argv:
        dd = sys.argv[sys.argv.index("--dir") + 1]
        st = json.load(open(os.path.join(dd, "start.json")))
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
    print("mode", st.get("mode"), "deadline", st.get("deadline"), "uar", st.get("unique_attempts_remaining"),
          "nq", len(st["questions"]), "nids", len(st.get("answer_ids") or []))
    files = []
    for r in raws:
        files += unzip_all(r)
    ans, unk = solve(st, files)
    nsets = len({q.get("set") for q in st["questions"]})
    if "--dir" not in sys.argv and any(len(u) == 2 and str(u[1]).startswith("NOFILE") for u in unk):
        for d in range(1, max(nsets, 2)):
            try:
                files += unzip_all(g.artifact(ch, d))
            except Exception as ex:
                print("delivery", d, "ERR", ex)
        ans, unk = solve(st, files)
    sub = map_ids(st, ans)
    print("computed %d/%d in %.2fs; unknown %d" % (len(sub), len(st.get("answer_ids") or []), time.time() - t0, len(unk)))
    if "--submit" in sys.argv and sub:
        r = g.submit(ch, sub)
        print("SUBMIT", len(sub), {k: r.get(k) for k in ("result", "flag", "error", "remaining")}, "%.2fs" % (time.time() - t0))
    for k, v in list(sub.items())[:400]:
        print("  %-70s %r" % (k, v))
    for u in unk:
        print("  UNK", u)
