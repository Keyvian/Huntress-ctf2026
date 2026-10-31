"""Day-15 metadata 'A Word to the Wise' solver (any mode). Superset of m14 (+ ooxml.<field> via ooxml.py: rels walked per .rels part
in archive order, document order; json answers = compact JSON). m14 = superset of m13 (PE header + VS_VERSIONINFO + .NET + MSI fields) +
LNK fields via lnk.py (lnk.target_path_windows = LinkInfo LocalBasePath+suffix > net share > IDList path > env block;
generic lnk.<snake> -> parsed header/LinkInfo/StringData/ExtraData keys, see LNK_ALIASES).
usage: m14.py <challenge> [start|retry|practice|none] [--submit] [--dir cached] [--save outdir]   (env GUID_STYLE)"""
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


# ------------------------------------------------------------------ legacy fields (day 4-7, from day09/m9.py)
cj = lambda x: json.dumps(x, separators=(",", ":"))


def text_bom(b):
    return "true" if b.startswith(b"\xef\xbb\xbf") else "false"


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


FIELDS = {
    "text.utf8_bom_present": text_bom,
    "jpeg.sof_dimensions_pixels": jpeg_sof,
    "png.ihdr_dimensions_pixels": png_ihdr,
    "pdf.header_version": pdf_ver,
    "zip.eocd_total_entries": zip_eocd_total,
    "zip.central_directory_member_names": zip_cd_names,
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


# ------------------------------------------------------------------ MSI (day 13)
# braces_upper graded CORRECT for msi.product_code_guid (day-13 single_solve) = Property value verbatim
GUID_STYLE = os.environ.get("GUID_STYLE", "braces_upper")  # upper | lower | braces_upper | braces_lower
_MCACHE = {}


def fmt_guid(v):
    g = v.strip().strip("{}")
    if not re.fullmatch(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}", g):
        return v
    g = g.lower() if GUID_STYLE.endswith("lower") else g.upper()
    return "{%s}" % g if GUID_STYLE.startswith("braces") else g


def msi_info(b):
    k = hashlib.sha1(b).digest()
    if k not in _MCACHE:
        from msi import MSI
        m = MSI(b)
        _MCACHE[k] = (m.properties(), m.summary(), m)
    return _MCACHE[k]


MSI_ALIASES = {"package_code": ("summary", "revision_number"), "revision_number": ("summary", "revision_number"),
               "template": ("summary", "template"), "platform": ("summary", "template"),
               "creating_application": ("summary", "creating_application"), "title": ("summary", "title"),
               "subject": ("summary", "subject"), "author": ("summary", "author"), "comments": ("summary", "comments")}


def msi_field(b, snake):
    props, summ, m = msi_info(b)
    want = re.sub(r"_(guid|text|string|value|hex)$", "", snake)
    if want in MSI_ALIASES:
        src, key = MSI_ALIASES[want]
        v = summ.get(key) if src == "summary" else props.get(key)
    else:
        w = want.replace("_", "").lower()
        hits = [v for kk, v in props.items() if kk and kk.replace("_", "").lower() == w]
        if not hits:
            hits = [v for kk, v in summ.items() if kk.replace("_", "").lower() == w]
        if not hits:
            raise KeyError("no msi field %s (props %s)" % (snake, list(props)))
        v = hits[0]
    v = "" if v is None else str(v)
    return fmt_guid(v) if snake.endswith("_guid") or re.fullmatch(r"\{?[0-9A-Fa-f-]{36}\}?", v) else v


# ------------------------------------------------------------------ LNK (day 14)
LNK_ALIASES = {"target_path_windows": "__target", "target_path": "__target", "target": "__target",
               "description": "name_string", "name": "name_string", "comment": "name_string",
               "working_directory": "working_dir", "arguments": "command_line_arguments", "args": "command_line_arguments",
               "command_line": "command_line_arguments", "icon_path": "icon_location", "icon": "icon_location",
               "machine_id": "tracker_machine_id", "netbios_name": "tracker_machine_id",
               "volume_serial": "drive_serial_number_hex", "drive_serial_number": "drive_serial_number_hex",
               "volume_serial_number": "drive_serial_number_hex", "volume_serial_hex": "drive_serial_number_hex",
               "drive_serial_hex": "drive_serial_number_hex", "show_command": "show_command_name",
               "environment_target": "environment_variables_unicode", "env_target": "environment_variables_unicode",
               "known_folder": "known_folder_id", "known_folder_guid": "known_folder_id",
               "target_size": "file_size", "target_file_size": "file_size", "link_flags": "link_flags_hex",
               "file_attributes": "file_attributes_hex", "hotkey": "hotkey_hex", "network_share": "net_name",
               "net_name_text": "net_name", "unc_share": "net_name"}
_LCACHE = {}


def lnk_obj(b):
    k = hashlib.sha1(b).digest()
    if k not in _LCACHE:
        from lnk import LNK
        _LCACHE[k] = LNK(b)
    return _LCACHE[k]


def lnk_target(L):
    """where the link points: LinkInfo local path(+suffix) > LinkInfo network share > IDList path > env block."""
    c = L.target_candidates()
    for k in ("linkinfo_local", "linkinfo_network", "idlist", "vista_idlist", "environment", "relative_path"):
        if c.get(k):
            return c[k]
    return "none"


def lnk_field(b, snake):
    L = lnk_obj(b)
    i = L.info
    key = LNK_ALIASES.get(snake, snake)
    if key == "__target":
        return lnk_target(L)
    for cand in (key, key + "_unicode", key + "_hex", key + "_name"):
        if cand in i:
            v = i[cand]
            return "none" if v in (None, "") else (",".join(v) if isinstance(v, list) else str(v))
    w = key.replace("_", "").lower()
    for kk, v in i.items():
        if kk.replace("_", "").lower() == w:
            return "none" if v in (None, "") else str(v)
    raise KeyError("no lnk field %s (have %s)" % (snake, sorted(i)))


# ------------------------------------------------------------------ OOXML (day 15)
_OCACHE = {}
OOXML_ALIASES = {"external_targets": "external_relationship_targets", "external_relationships": "external_relationship_targets",
                 "internal_targets": "internal_relationship_targets", "internal_relationships": "internal_relationship_targets"}


def ooxml_field(b, snake):
    k = hashlib.sha1(b).digest()
    if k not in _OCACHE:
        from ooxml import OOXML
        _OCACHE[k] = OOXML(b)
    i = _OCACHE[k].info
    key = OOXML_ALIASES.get(snake, snake)
    if key not in i:
        w = key.replace("_", "").lower()
        hit = [kk for kk in i if kk.replace("_", "").lower() == w]
        if not hit:
            raise KeyError("no ooxml field %s (have %s)" % (snake, sorted(i)))
        key = hit[0]
    v = i[key]
    if isinstance(v, (list, dict)):
        return json.dumps(v, separators=(",", ":"), ensure_ascii=False)
    return str(v)


def field_value(fld, b):
    m = re.fullmatch(r"ooxml\.(\w+)", fld or "")
    if m:
        return ooxml_field(b, m.group(1))
    if fld in FIELDS:
        return FIELDS[fld](b)
    m = re.fullmatch(r"lnk\.(\w+)", fld or "")
    if m:
        return lnk_field(b, m.group(1))
    m = re.fullmatch(r"msi\.(\w+)", fld or "")
    if m:
        return msi_field(b, m.group(1))
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
        if sid.endswith("-filename") and "Determine" not in text:
            # stem of the id ('evidence-note' / 'evidence-note-copy' / 'roster') == member name minus extension, in this set's container
            stem, cont = sid[:-len("-filename")], art.split("->")[0].strip()
            ex = sorted({os.path.basename(pp) for pp, _ in files if os.path.splitext(os.path.basename(pp))[0] == stem
                         and (not cont or cont in pp.split("/") or len(pp.split("/")) == 1)})
            if len(ex) == 1:
                ans[qid] = ex[0]; continue
            pre = sid.rsplit("filename", 1)[0]
            sib = [x.get("artifact", "") for x in st["questions"] if x["id"].split(".", 1)[-1].startswith(pre) and x.get("set") == q.get("set") and "->" in x.get("artifact", "")]
            ans[qid] = sib[0].split("->")[-1].strip() if sib else "UNKNOWN"
            if not sib: unk.append((qid, "filename?", text))
            continue
        mo = re.search(r"in ascending digest order\. Files: (\[.*\])", text)
        if mo:
            names = json.loads(mo.group(1)); cont = art.split("->")[0].strip()
            dig = []
            for nm in names:
                pp, bb = find_member(files, cont + " -> " + nm, setno)
                if bb is None: break
                dig.append((hashlib.sha256(bb).hexdigest(), nm))
            if len(dig) == len(names):
                ans[qid] = cj([nm for _, nm in sorted(dig)])
            else:
                unk.append((qid, "NOFILE synth", names))
            continue
        p, b = find_member(files, art, setno)
        if b is None:
            unk.append((qid, "NOFILE " + art)); continue
        if re.search(r"-magic-prefix-hex-(\d+)$", sid):
            ans[qid] = b[:int(re.search(r"-magic-prefix-hex-(\d+)$", sid).group(1))].hex(); continue
        if re.search(r"-(?:magic-suffix-hex|last)-(\d+)$", sid):
            ans[qid] = b[-int(re.search(r"-(?:magic-suffix-hex|last)-(\d+)$", sid).group(1)):].hex(); continue
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
