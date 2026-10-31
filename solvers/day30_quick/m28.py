"""Day-28 metadata 'Where It All Began' solver = m27 + disk.<field> (disk.py: MBR/EBR/GPT). Day-27 doc:
Day-27 metadata 'Packet Loss Prevention' solver (any mode) = m26 (Day 1-26 cumulative contract incl. registry.*, prefetch.*)
+ pcap.<field> for packet captures (pcap.py: classic libpcap LE/BE usec/nsec + pcapng, strict record validation).
usage: m27.py <challenge> [start|retry|practice|none] [--submit] [--partial] [--dir cached] [--save outdir]
       [--override id=value ...] [--run-for-time]      offline: m27.py x none --dir <saved dir>"""
import sys, os, re, json, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import m15, m26, pcap, disk
from m15 import unzip_all, map_ids
from m16 import fix_json_kind
from m20 import overrides

PCAP_RE = re.compile(r"(?:pcap|pcapng|capture|disk)\.(\w+)")


def field_value(fld, b):
    mo = PCAP_RE.fullmatch(fld or "")
    if mo:
        if fld.startswith("disk."):
            return disk.field(b, mo.group(1))
        return pcap.field(b, mo.group(1))
    return m26.field_value(fld, b)


m15.field_value = field_value
_m26_solve = m26.solve


def solve(st, files):
    """m26.solve + re-resolve every `Determine pcap.<field> for` question (same shape as Days 23-26)."""
    ans, unk = _m26_solve(st, files)
    unk = [u for u in unk if not (len(u) > 1 and PCAP_RE.fullmatch(str(u[1])))]
    for q in st["questions"]:
        mo = re.search(r"Determine ((?:pcap|pcapng|capture|disk)\.\w+) for", q["question"])
        if not mo:
            continue
        m = re.match(r"set(\d+)\.", q["id"])
        setno = int(m.group(1)) if m else q.get("set")
        p, b = m15.find_member(files, q.get("artifact") or "", setno)
        if b is None:
            unk.append((q["id"], mo.group(1), "NOFILE " + str(q.get("artifact"))))
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
    if "--dir" not in sys.argv and any(any(str(x).startswith("NOFILE") for x in u[1:3]) for u in unk):
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
        if b[:4] in pcap.MAGICS or b[:4] == b"\x0a\x0d\x0d\x0a" or p.lower().endswith((".pcap", ".pcapng", ".cap")):
            try:
                i = pcap.parse(b)
                print("  PCAP %s size %d fmt %s %s ver %s link %s snap %s pkts %d errs %s lens %s payloads %r" % (
                    p, len(b), i.get("format"), i.get("endianness"), i.get("version"), i.get("linktype"), i.get("snaplen"),
                    i["packet_count"], i["errors"], [(x["incl_len"], x["orig_len"]) for x in i["packets"]][:12],
                    [x[:24] for x in i["payloads"]][:6]))
            except Exception as ex:
                print("  PCAP", p, "parse error", repr(ex))
    for p, b in files:
        if p.lower().endswith((".img", ".dd", ".raw", ".vhd")):
            try:
                i = disk.parse(b)
                print("  DISK %s size %d scheme %s ss %s used %s pv %s bv %s errs %s parts %s" % (p, len(b), i["scheme"], i["sector_size"], i.get("gpt_used"), i.get("gpt_primary_valid"), i.get("gpt_backup_valid"), i["errors"], [(x["index"], x["kind"], x.get("type") or x.get("type_guid"), x["start"], x["end"], x.get("name")) for x in i["partitions"]]))
            except Exception as ex:
                print("  DISK", p, "parse error", repr(ex))
    print("computed %d/%d in %.2fs; unknown %d" % (len(sub), len(st.get("answer_ids") or []), time.time() - t0, len(unk)))
    for k, v in list(sub.items())[:800]:
        if "pcap" in k or "disk" in k or "synthesis" in k or "UNK" in k or "filename" in k:
            print("  %-70s %r" % (k, v))
    for u in unk:
        print("  UNK", u)
    if "--submit" in sys.argv and sub:
        if len(sub) != len(st.get("answer_ids") or []) and "--partial" not in sys.argv:
            print("ABORT submit: incomplete (use --partial to submit anyway)"); sys.exit(2)
        r = g.submit(ch, sub)
        print("SUBMIT", len(sub), {k: r.get(k) for k in ("result", "flag", "error", "remaining")}, "%.2fs" % (time.time() - t0))
