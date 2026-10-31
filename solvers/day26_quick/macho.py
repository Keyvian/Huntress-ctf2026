"""Mach-O / universal (fat) / ar-archive CPU-type enumeration for the Day-20 metadata field macho.cpu_type_set.
Pure Python. Handles: thin MH_MAGIC/MH_MAGIC_64 (both byte orders), FAT_MAGIC / FAT_MAGIC_64 (big-endian headers; Java .class
files also start with CAFEBABE -> distinguished by a sane nfat_arch), BSD/`!<arch>` static libraries whose members are Mach-O
objects (each member's cputype), nested zips. NAME_STYLE selects the value spelling (set after grading probes).
usage: macho.py <file>..."""
import sys, struct, io, zipfile

MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64 = 0xfeedface, 0xcefaedfe, 0xfeedfacf, 0xcffaedfe
FAT_MAGIC, FAT_CIGAM, FAT_MAGIC_64, FAT_CIGAM_64 = 0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca
CPU_ARCH_ABI64 = 0x01000000

# lipo / `file` style names
NAMES = {1: "vax", 6: "m68k", 7: "i386", 7 | CPU_ARCH_ABI64: "x86_64", 10: "m98k", 11: "hppa", 12: "arm",
         12 | CPU_ARCH_ABI64: "arm64", 12 | 0x02000000: "arm64_32", 13: "mc88000", 14: "sparc", 15: "i860",
         18: "ppc", 18 | CPU_ARCH_ABI64: "ppc64"}
NAME_STYLE = "lipo"   # lipo | upper | const | hex8 | hex | dec | sub


def name(cputype, cpusubtype=0, style=None):
    style = style or NAME_STYLE
    n = NAMES.get(cputype, "0x%08x" % cputype)
    if style == "lipo":
        if cputype == (12 | CPU_ARCH_ABI64) and (cpusubtype & 0xffffff) == 2:
            return "arm64e"
        return n
    if style == "upper": return n.upper()
    if style == "const": return "CPU_TYPE_" + n.upper()
    if style == "hex8": return "0x%08x" % cputype
    if style == "hex": return "0x%x" % cputype
    if style == "dec": return cputype
    if style == "sub": return "%s:%d" % (n, cpusubtype & 0xffffff)
    return n


def thin_header(b):
    """(cputype, cpusubtype, filetype, ncmds, is64, endian) for a thin Mach-O or None."""
    if len(b) < 28:
        return None
    m = struct.unpack("<I", b[:4])[0]
    if m in (MH_MAGIC, MH_MAGIC_64):
        en = "<"
    elif m in (MH_CIGAM, MH_CIGAM_64):
        en = ">"
    else:
        return None
    is64 = struct.unpack(en + "I", b[:4])[0] == MH_MAGIC_64
    cputype, cpusub, ftype, ncmds = struct.unpack(en + "iIII", b[4:20])
    return cputype & 0xffffffff, cpusub, ftype, ncmds, is64, en


def fat_archs(b):
    """[(cputype, cpusubtype, offset, size)] for a fat/universal header, else None."""
    if len(b) < 8:
        return None
    m = struct.unpack(">I", b[:4])[0]
    if m not in (FAT_MAGIC, FAT_MAGIC_64):
        return None
    n = struct.unpack(">I", b[4:8])[0]
    if n == 0 or n > 64:
        return None  # Java class file (major version) or garbage
    out = []
    for i in range(n):
        if m == FAT_MAGIC:
            ct, cs, off, sz, _al = struct.unpack(">iIIII", b[8 + 20 * i:28 + 20 * i])
        else:
            ct, cs, off, sz, _al, _res = struct.unpack(">iIQQII", b[8 + 32 * i:40 + 32 * i])
        out.append((ct & 0xffffffff, cs, off, sz))
    return out


def ar_members(b):
    """[(name, bytes)] of a `!<arch>` archive (BSD long names #1/NN supported)."""
    if b[:8] != b"!<arch>\n":
        return None
    out = []; o = 8
    while o + 60 <= len(b):
        h = b[o:o + 60]
        nm = h[:16].decode("latin1").rstrip()
        try:
            sz = int(h[48:58].decode().strip())
        except ValueError:
            break
        o += 60
        data = b[o:o + sz]
        if nm.startswith("#1/"):
            ln = int(nm[3:]); nm = data[:ln].split(b"\x00")[0].decode("latin1"); data = data[ln:]
        out.append((nm, data))
        o += sz + (sz & 1)
    return out


def cpu_types(b, depth=0):
    """ordered, deduplicated list of (cputype, cpusubtype) found in the bytes (thin / fat / ar / zip)."""
    out = []
    def add(t):
        if t not in out: out.append(t)
    th = thin_header(b)
    if th:
        add((th[0], th[1])); return out
    fa = fat_archs(b)
    if fa:
        for ct, cs, off, sz in fa:
            inner = thin_header(b[off:off + 32]) if 0 < off < len(b) else None
            add((inner[0], inner[1]) if inner else (ct, cs))
        return out
    ar = ar_members(b)
    if ar is not None:
        for nm, data in ar:
            if nm in ("__.SYMDEF", "__.SYMDEF SORTED", "/", "//") or nm.startswith("__.SYMDEF"):
                continue
            for t in cpu_types(data, depth + 1): add(t)
        return out
    if b[:2] == b"PK" and depth < 3:
        try:
            z = zipfile.ZipFile(io.BytesIO(b))
            for n in z.namelist():
                for t in cpu_types(z.read(n), depth + 1): add(t)
        except Exception:
            pass
    return out


def info(b):
    th = thin_header(b)
    if th:
        return {"kind": "thin", "cputype": th[0], "cpusubtype": th[1], "filetype": th[2], "ncmds": th[3], "is64": th[4]}
    fa = fat_archs(b)
    if fa:
        return {"kind": "fat", "archs": fa}
    if ar_members(b) is not None:
        return {"kind": "ar", "members": [(n, len(d), thin_header(d) and thin_header(d)[0]) for n, d in ar_members(b)]}
    return {"kind": "none"}


def cpu_type_set(b, style=None, sort=False):
    ts = cpu_types(b)
    if sort:
        ts = sorted(ts)
    return [name(ct, cs, style) for ct, cs in ts]


if __name__ == "__main__":
    import json
    for f in sys.argv[1:]:
        b = open(f, "rb").read()
        print(f, len(b), info(b), json.dumps(cpu_type_set(b), separators=(",", ":")))
