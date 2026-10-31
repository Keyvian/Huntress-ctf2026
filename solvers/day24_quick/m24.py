"""Day-24 metadata 'Event Horizon' solver (any mode) = m23 (Day 1-23 cumulative contract incl. sqlite.*) + evtx.<field>
for Windows event logs (evtx.py: file header / chunk headers / record walk / CRCs; record_count = complete records actually
present, not the header's next_record_id - 1).
usage: m24.py <challenge> [start|retry|practice|none] [--submit] [--partial] [--dir cached] [--save outdir]
       [--override id=value ...] [--run-for-time]      offline: m24.py x none --dir <saved dir>"""
import sys, os, re, json, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import m15, m23, evtx
from m15 import unzip_all, map_ids
from m16 import fix_json_kind
from m20 import overrides

EVTX_RE = re.compile(r"(?:evtx|evt|eventlog|event_log|events)\.(\w+)")


def field_value(fld, b):
    mo = EVTX_RE.fullmatch(fld or "")
    if mo:
        return evtx.field(b, mo.group(1))
    return m23.field_value(fld, b)


m15.field_value = field_value
_m23_solve = m23.solve


def solve(st, files):
    """m23.solve + re-resolve every `Determine evtx.<field>` question (same reason as m23's sqlite re-resolve: m15 answers ids
    ending in -size-bytes / -md5 / -sha* with the whole-file value before reading the question text)."""
    ans, unk = _m23_solve(st, files)
    # Day-24 mastery lesson: `set6.roster-filename` had NO sibling roster-* question (only evidence-note ones), so m15's
    # stem==basename / sibling-artifact inference returned "UNKNOWN". Fall back to the container's own member list:
    # a unique member named <stem>.<ext> or <stem>-<6 hex>.<ext> (the 6-hex tag excludes the longer `evidence-note-copy-…`
    # stem when resolving `evidence-note`).
    for q in st["questions"]:
        qid, text, art = q["id"], q["question"], q.get("artifact") or ""
        m = re.match(r"set(\d+)\.", qid)
        sid = qid.split(".", 1)[1] if m else qid
        if not (sid.endswith("-filename") and "Determine" not in text):
            continue
        stem, cont = sid[:-len("-filename")], art.split("->")[0].strip()
        pat = re.compile(r"^%s(?:-[0-9a-f]{6})?\.\w+$" % re.escape(stem))
        ex = sorted({os.path.basename(pp) for pp, _ in files
                     if pat.match(os.path.basename(pp)) and (not cont or cont in pp.split("/") or len(pp.split("/")) == 1)})
        if len(ex) == 1:
            # authoritative when unique: m15's sibling inference answered `set5.evidence-note-filename` with the
            # `evidence-note-copy-…` sibling's artifact although `evidence-note-<6hex>.txt` exists in that container
            if ans.get(qid) != ex[0]:
                print("  filename override", qid, ans.get(qid), "->", ex[0])
            ans[qid] = ex[0]
            unk = [u for u in unk if u[0] != qid]
        elif ans.get(qid) in (None, "UNKNOWN"):
            unk.append((qid, "filename-fallback", ex))
    for q in st["questions"]:
        mo = re.search(r"Determine ((?:evtx|evt|eventlog|event_log|events)\.\w+) for", q["question"])
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
        if b[:8] == evtx.MAGIC or p.lower().endswith(".evtx"):
            try:
                i = evtx.info(b)
                print("  EVTX %s size %d hdr_chunks %d chunks %d(valid %d complete %d) next_id %d claimed %d chunk_claimed %d WALKED %d uniq %d dup %d "
                      "trunc %s partial %s crc(hdr %s chunks %s recs %s) ids %s..%s" % (
                          p, len(b), i["header_chunk_count"], i["chunk_count"], i["valid_chunk_count"], i["complete_chunk_count"],
                          i["next_record_id"], i["claimed_record_count"], i["chunk_claimed_record_count"], i["record_count"],
                          i["unique_record_id_count"], i["duplicate_record_count"], i["truncated"], i["any_partial_record"],
                          i["header_crc32_valid"], i["chunks_crc32_all_valid"], i["records_crc32_all_valid"], i["first_record_id"], i["last_record_id"]))
            except Exception as ex:
                print("  EVTX", p, "parse error", repr(ex))
    print("computed %d/%d in %.2fs; unknown %d" % (len(sub), len(st.get("answer_ids") or []), time.time() - t0, len(unk)))
    for k, v in list(sub.items())[:600]:
        if "evtx" in k or "synthesis" in k or "UNK" in k:
            print("  %-70s %r" % (k, v))
    for u in unk:
        print("  UNK", u)
    if "--submit" in sys.argv and sub:
        if len(sub) != len(st.get("answer_ids") or []) and "--partial" not in sys.argv:
            print("ABORT submit: incomplete (use --partial to submit anyway)"); sys.exit(2)
        r = g.submit(ch, sub)
        print("SUBMIT", len(sub), {k: r.get(k) for k in ("result", "flag", "error", "remaining")}, "%.2fs" % (time.time() - t0))
