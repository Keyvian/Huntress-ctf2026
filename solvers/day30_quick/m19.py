"""Day-19 metadata 'Little Endian on the Prairie' solver (any mode) = m18 (+ all prior-day fields) + elf.<field> from the ELF header.
elf.e_machine_u16_hex -> "0x%04x" of e_machine read with the header's own byte order (EI_DATA); generic elf.e_<name>[_uNN_hex|_hex]
for every e_ident / ELF header field (class, endianness, type, machine name, entry, phnum, shnum...). Non-ELF bytes -> "none".
usage: m19.py <challenge> [start|retry|practice|none] [--submit] [--dir cached] [--save outdir] [--override id=value ...]
       (--run-for-time adds run_for_time:true to the start/retry body)"""
import sys, os, re, json, time, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import m15, m16, m17, m18
from m15 import unzip_all, solve, map_ids, cj
from m16 import fix_json_kind
import media, video

ELF_MACHINES = {0x00: "none", 0x02: "sparc", 0x03: "i386", 0x08: "mips", 0x14: "powerpc", 0x15: "powerpc64", 0x16: "s390",
                0x28: "arm", 0x2a: "superh", 0x32: "ia64", 0x3e: "x86-64", 0xb7: "aarch64", 0xf3: "riscv", 0xf7: "bpf",
                0x102: "loongarch"}
ELF_TYPES = {0: "ET_NONE", 1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN", 4: "ET_CORE"}
ELF_OSABI = {0: "SYSV", 1: "HPUX", 2: "NETBSD", 3: "GNU", 6: "SOLARIS", 9: "FREEBSD", 12: "OPENBSD"}


def elf_info(b):
    """ELF header fields (dict) or None if the bytes are not an ELF."""
    if len(b) < 0x34 or b[:4] != b"\x7fELF":
        return None
    cls, data, ver, osabi, abiver = b[4], b[5], b[6], b[7], b[8]
    en = "<" if data == 1 else ">"
    d = {"ei_class": cls, "ei_data": data, "ei_version": ver, "ei_osabi": osabi, "ei_abiversion": abiver,
         "class": "ELF64" if cls == 2 else ("ELF32" if cls == 1 else "none"),
         "endianness": "little" if data == 1 else ("big" if data == 2 else "none"), "bits": 64 if cls == 2 else 32}
    d["e_type"], d["e_machine"], d["e_version"] = struct.unpack(en + "HHI", b[16:24])
    if cls == 2 and len(b) >= 64:
        d["e_entry"], d["e_phoff"], d["e_shoff"] = struct.unpack(en + "QQQ", b[24:48]); o = 48
    else:
        d["e_entry"], d["e_phoff"], d["e_shoff"] = struct.unpack(en + "III", b[24:36]); o = 36
    (d["e_flags"], d["e_ehsize"], d["e_phentsize"], d["e_phnum"], d["e_shentsize"], d["e_shnum"],
     d["e_shstrndx"]) = struct.unpack(en + "IHHHHHH", b[o:o + 16])
    d["machine_name"] = ELF_MACHINES.get(d["e_machine"], "0x%04x" % d["e_machine"])
    d["type_name"] = ELF_TYPES.get(d["e_type"], "0x%04x" % d["e_type"])
    d["osabi_name"] = ELF_OSABI.get(osabi, str(osabi))
    return d


def elf_field(b, snake):
    i = elf_info(b)
    if i is None:
        return "none"
    s = snake.lower()
    m = re.fullmatch(r"(\w+?)_u(8|16|32|64)_hex", s)
    if m:
        v = i.get(m.group(1), i.get("e_" + m.group(1)))
        if v is None: raise KeyError("no elf field %s (have %s)" % (snake, sorted(i)))
        return "0x%0*x" % (int(m.group(2)) // 4, int(v))
    m = re.fullmatch(r"(\w+?)_hex", s)
    if m:
        v = i.get(m.group(1), i.get("e_" + m.group(1)))
        if v is None: raise KeyError("no elf field %s (have %s)" % (snake, sorted(i)))
        return "0x%x" % int(v)
    m = re.fullmatch(r"(\w+?)_(dec|int|u8|u16|u32|u64)", s)
    if m:
        v = i.get(m.group(1), i.get("e_" + m.group(1)))
        if v is None: raise KeyError("no elf field %s (have %s)" % (snake, sorted(i)))
        return str(int(v))
    alias = {"elf_class": "class", "ei_class_name": "class", "class_name": "class", "e_ident_class": "class",
             "endian": "endianness", "byte_order": "endianness", "ei_data_name": "endianness", "data": "endianness",
             "e_type_name": "type_name", "elf_type": "type_name", "type": "type_name",
             "e_machine_name": "machine_name", "machine": "machine_name", "architecture": "machine_name", "arch": "machine_name",
             "e_osabi": "osabi_name", "osabi": "osabi_name", "os_abi": "osabi_name", "ei_osabi_name": "osabi_name",
             "entry": "e_entry", "entry_point": "e_entry", "e_entry_point": "e_entry"}
    k = alias.get(s, s)
    if k in i:
        v = i[k]
        if k in ("e_entry",):
            return "0x%x" % v
        return str(v)
    if "e_" + k in i:
        return str(i["e_" + k])
    raise KeyError("no elf field %s (have %s)" % (snake, sorted(i)))


def field_value(fld, b):
    mo = re.fullmatch(r"elf\.(\w+)", fld or "")
    if mo:
        return elf_field(b, mo.group(1))
    mo = re.fullmatch(r"(?:media|video|stream)\.(\w+)", fld or "")
    if mo and ("video" in mo.group(1) or "frame" in mo.group(1) or "rotation" in mo.group(1) or "dimension" in mo.group(1)
               or "aspect" in mo.group(1) or "pix_fmt" in mo.group(1) or mo.group(1) in ("width", "height")):
        try:
            return video.video_field(b, mo.group(1))
        except KeyError:
            pass
    return m17.field_value(fld, b)


m15.field_value = field_value


def overrides(argv):
    out = {}
    for i, a in enumerate(argv):
        if a == "--override":
            k, v = argv[i + 1].split("=", 1)
            out[k] = v
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
        body = {"op": op, "challenge": ch}
        if "--run-for-time" in sys.argv:
            body["run_for_time"] = True
        st = g.post(body) if op != "none" else g.status(ch)
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
    sub = fix_json_kind(st, map_ids(st, ans))
    sub.update(overrides(sys.argv))
    if "--video-info" in sys.argv:
        for p, b in files:
            i = video.probe(b)
            if i.get("video"):
                v = i["video"]
                print("  VIDEO", p, json.dumps({k: x for k, x in v.items() if k not in ("stsd_entries", "stts", "matrix")}, default=str)[:900])
    print("computed %d/%d in %.2fs; unknown %d" % (len(sub), len(st.get("answer_ids") or []), time.time() - t0, len(unk)))
    if "--submit" in sys.argv and sub:
        r = g.submit(ch, sub)
        print("SUBMIT", len(sub), {k: r.get(k) for k in ("result", "flag", "error", "remaining")}, "%.2fs" % (time.time() - t0))
    for k, v in list(sub.items())[:400]:
        print("  %-70s %r" % (k, v))
    for u in unk:
        print("  UNK", u)
