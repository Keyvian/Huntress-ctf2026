"""Day-20 metadata 'Universal Appeal' solver (any mode) = m19 (+ all prior-day fields) + macho.<field> for Mach-O artifacts.
macho.cpu_type_set -> compact JSON array of every CPU type in the file as "0x%08x" of cputype (graded CORRECT on single_solve:
thin arm64 -> ["0x0100000c"]), in file order (fat_arch order for universal binaries, member order for `!<arch>` static
libraries), deduplicated. See macho.py for the parser (thin / fat / ar / nested zip).
usage: m20.py <challenge> [start|retry|practice|none] [--submit] [--dir cached] [--save outdir] [--override id=value ...]
       [--run-for-time] [--sorted] (sort the cpu set numerically instead of file order)"""
import sys, os, re, json, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import m15, m19, macho
from m15 import unzip_all, solve, map_ids, cj
from m16 import fix_json_kind

SORTED = "--sorted" in sys.argv
STYLE = "hex8"


def macho_field(b, snake):
    s = snake.lower()
    if s in ("cpu_type_set", "cputype_set", "cpu_types", "cpu_type_list", "arch_set", "architectures"):
        ts = macho.cpu_types(b)
        if SORTED:
            ts = sorted(ts)
        out = []
        for ct, cs in ts:
            v = macho.name(ct, cs, STYLE)
            if v not in out:
                out.append(v)
        return cj(out)
    if s in ("cpu_type_name_set", "arch_names"):
        return cj(macho.cpu_type_set(b, "lipo", SORTED))
    i = macho.info(b)
    if i["kind"] == "none":
        return "none"
    if s in ("is_fat", "is_universal", "universal"):
        return "true" if i["kind"] == "fat" else "false"
    if s in ("arch_count", "nfat_arch", "cpu_type_count"):
        return str(len(macho.cpu_types(b)))
    if i["kind"] == "thin":
        if s in ("cpu_type_u32_hex", "cputype_u32_hex", "cpu_type_hex"):
            return "0x%08x" % i["cputype"]
        if s in ("cpu_subtype_u32_hex", "cpusubtype_u32_hex"):
            return "0x%08x" % i["cpusubtype"]
        if s in ("cpu_type", "cputype"):
            return str(i["cputype"])
        if s in ("cpu_subtype", "cpusubtype"):
            return str(i["cpusubtype"])
        if s in ("cpu_type_name", "arch", "architecture"):
            return macho.name(i["cputype"], i["cpusubtype"], "lipo")
        if s in ("filetype", "file_type"):
            return str(i["filetype"])
        if s in ("filetype_u32_hex", "file_type_u32_hex"):
            return "0x%08x" % i["filetype"]
        if s in ("ncmds", "load_command_count"):
            return str(i["ncmds"])
        if s in ("magic", "magic_u32_hex"):
            return "0x%08x" % (0xfeedfacf if i["is64"] else 0xfeedface)
        if s in ("is_64bit", "is64"):
            return "true" if i["is64"] else "false"
    raise KeyError("unknown macho field %s" % snake)


def field_value(fld, b):
    mo = re.fullmatch(r"(?:macho|mach_o|mach-o)\.(\w+)", fld or "")
    if mo:
        return macho_field(b, mo.group(1))
    return m19.field_value(fld, b)


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
                b = g.artifact(ch, d)
                if "--save" in sys.argv:
                    open(os.path.join(sd, "artifact%d.bin" % d), "wb").write(b)
                files += unzip_all(b)
            except Exception as ex:
                print("delivery", d, "ERR", ex)
        ans, unk = solve(st, files)
    sub = fix_json_kind(st, map_ids(st, ans))
    sub.update(overrides(sys.argv))
    for p, b in files:
        i = macho.info(b)
        if i["kind"] != "none":
            print("  MACHO", p, len(b), i, cj(macho.cpu_type_set(b, "lipo")))
    print("computed %d/%d in %.2fs; unknown %d" % (len(sub), len(st.get("answer_ids") or []), time.time() - t0, len(unk)))
    if "--submit" in sys.argv and sub:
        r = g.submit(ch, sub)
        print("SUBMIT", len(sub), {k: r.get(k) for k in ("result", "flag", "error", "remaining")}, "%.2fs" % (time.time() - t0))
    for k, v in list(sub.items())[:400]:
        if "macho" in k or "synthesis" in k or "UNK" in k:
            print("  %-70s %r" % (k, v))
    for u in unk:
        print("  UNK", u)
