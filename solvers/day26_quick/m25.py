"""Day-25 metadata 'Hive Mind' solver (any mode) = m24 (Day 1-24 cumulative contract incl. evtx.*) + registry.<field>
for Windows registry hives (reghive.py: regf base block, hbins, nk/vk/sk cells; hive_root_name = the ROOT nk cell's key
name, NOT the header's embedded (renamed) file name).
usage: m25.py <challenge> [start|retry|practice|none] [--submit] [--partial] [--dir cached] [--save outdir]
       [--override id=value ...] [--run-for-time]      offline: m25.py x none --dir <saved dir>"""
import sys, os, re, json, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import m15, m24, reghive
from m15 import unzip_all, map_ids
from m16 import fix_json_kind
from m20 import overrides

REG_RE = re.compile(r"(?:registry|regf|hive|reg)\.(\w+)")


def field_value(fld, b):
    mo = REG_RE.fullmatch(fld or "")
    if mo:
        return reghive.field(b, mo.group(1))
    return m24.field_value(fld, b)


m15.field_value = field_value
_m24_solve = m24.solve


def solve(st, files):
    """m24.solve + re-resolve every `Determine registry.<field>` question (same reason as m23/m24: m15 answers ids ending in
    -size-bytes / -md5 / -sha* / -name with whole-file values before reading the question text)."""
    ans, unk = _m24_solve(st, files)
    for q in st["questions"]:
        mo = re.search(r"Determine ((?:registry|regf|hive|reg)\.\w+) for", q["question"])
        if not mo:
            continue
        m = re.match(r"set(\d+)\.", q["id"])
        setno = int(m.group(1)) if m else q.get("set")
        p, b = m15.find_member(files, q.get("artifact") or "", setno)
        if b is None:
            continue
        try:
            v = field_value(mo.group(1), b)
            if isinstance(v, bool):
                v = "true" if v else "false"
            elif isinstance(v, (list, dict)):
                v = json.dumps(v, separators=(",", ":"), ensure_ascii=False)
            elif v is None:
                v = "none"
            ans[q["id"]] = str(v)
        except Exception as ex:
            unk.append((q["id"], mo.group(1), p, repr(ex)))
    return ans, unk


if __name__ == "__main__":
    from gmx import GMX
    ch = sys.argv[1]
    op = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith("--") else "start"
    t0 = time.time()
    g = GMX()
    sd = None
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
                if sd:
                    open(os.path.join(sd, "artifact%d.bin" % d), "wb").write(b)
                files += unzip_all(b)
            except Exception as ex:
                print("delivery", d, "ERR", ex)
        ans, unk = solve(st, files)
    sub = fix_json_kind(st, map_ids(st, ans))
    sub.update(overrides(sys.argv))
    for p, b in files:
        if b[:4] == reghive.MAGIC or p.lower().endswith((".hiv", ".hive", ".dat")):
            try:
                i = reghive.info(b)
                print("  REGF %s size %d seq %d/%d match %s ver %s type %s root@0x%x ROOT %r hdrname %r chk %s bins %d(size %d/%d) "
                      "keys %d values %d rootvals %s" % (
                          p, len(b), i["primary_sequence_number"], i["secondary_sequence_number"], i["sequence_numbers_match"],
                          i["version"], i["file_type_name"], i["root_cell_offset"], i.get("hive_root_name"), i["header_file_name"],
                          i["checksum_valid"], i["hbin_count"], i["hbin_total_size"], i["hive_bins_data_size"], i.get("key_count"),
                          i.get("value_count_total"), json.dumps(i.get("root_values"), default=str)))
            except Exception as ex:
                print("  REGF", p, "parse error", repr(ex))
    print("computed %d/%d in %.2fs; unknown %d" % (len(sub), len(st.get("answer_ids") or []), time.time() - t0, len(unk)))
    for k, v in list(sub.items())[:800]:
        if "registry" in k or "synthesis" in k or "UNK" in k or "filename" in k:
            print("  %-70s %r" % (k, v))
    for u in unk:
        print("  UNK", u)
    if "--submit" in sys.argv and sub:
        if len(sub) != len(st.get("answer_ids") or []) and "--partial" not in sys.argv:
            print("ABORT submit: incomplete (use --partial to submit anyway)"); sys.exit(2)
        r = g.submit(ch, sub)
        print("SUBMIT", len(sub), {k: r.get(k) for k in ("result", "flag", "error", "remaining")}, "%.2fs" % (time.time() - t0))
