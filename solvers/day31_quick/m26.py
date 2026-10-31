"""Day-26 metadata 'Before You Go' solver (any mode) = m25 (Day 1-25 cumulative contract incl. registry.*) + prefetch.<field>
for Windows Prefetch files (prefetch.py: MAM/LZXPRESS-Huffman decompression + SCCA header; executable_name = the UTF-16LE
name at offset 16 of the DECOMPRESSED header - the on-disk `trace-001.pf` label is the renamed decoy the prompt warns about).
usage: m26.py <challenge> [start|retry|practice|none] [--submit] [--partial] [--dir cached] [--save outdir]
       [--override id=value ...] [--run-for-time]      offline: m26.py x none --dir <saved dir>"""
import sys, os, re, json, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import m15, m25, prefetch, reghive
from m15 import unzip_all, map_ids
from m16 import fix_json_kind
from m20 import overrides

PF_RE = re.compile(r"(?:prefetch|pf|scca)\.(\w+)")


def field_value(fld, b):
    mo = PF_RE.fullmatch(fld or "")
    if mo:
        return prefetch.field(b, mo.group(1))
    return m25.field_value(fld, b)


m15.field_value = field_value
_m25_solve = m25.solve


def solve(st, files):
    """m25.solve + re-resolve every `Determine prefetch.<field>` question (m15 answers ids ending in -name etc. with whole-file
    values before reading the question text, so the lane-specific fields are re-resolved here as on Days 23-25)."""
    ans, unk = _m25_solve(st, files)
    for q in st["questions"]:
        mo = re.search(r"Determine ((?:prefetch|pf|scca)\.\w+) for", q["question"])
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
        if b[:3] == b"MAM" or b[4:8] == b"SCCA" or p.lower().endswith(".pf"):
            try:
                i = prefetch.parse(b)
                print("  PF %s size %d comp %s ver %s sig %s exe %r hash %s runs %s last %s vol %r serial %s files %d" % (
                    p, len(b), i.get("compressed"), i.get("format_version"), i.get("signature_valid"), i.get("executable_name"),
                    i.get("prefetch_hash_hex"), i.get("run_count"), i.get("last_run_time"), i.get("volume_device_path"),
                    i.get("volume_serial_number"), i.get("filename_count", 0)))
            except Exception as ex:
                print("  PF", p, "parse error", repr(ex))
    print("computed %d/%d in %.2fs; unknown %d" % (len(sub), len(st.get("answer_ids") or []), time.time() - t0, len(unk)))
    for k, v in list(sub.items())[:800]:
        if "prefetch" in k or "synthesis" in k or "UNK" in k or "filename" in k:
            print("  %-70s %r" % (k, v))
    for u in unk:
        print("  UNK", u)
    if "--submit" in sys.argv and sub:
        if len(sub) != len(st.get("answer_ids") or []) and "--partial" not in sys.argv:
            print("ABORT submit: incomplete (use --partial to submit anyway)"); sys.exit(2)
        r = g.submit(ch, sub)
        print("SUBMIT", len(sub), {k: r.get(k) for k in ("result", "flag", "error", "remaining")}, "%.2fs" % (time.time() - t0))
