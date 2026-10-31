"""Day-18 metadata 'Frame of Reference' solver (any mode) = m17 (+ all prior-day fields) + media.primary_video_* via video.py.
media.primary_video_dimensions -> ffprobe-style "<width>x<height>" of the first video stream (SPS-cropped for H.264/HEVC; falls
back to the stsd/tkhd geometry); also coded_dimensions, display_dimensions (tkhd), rotation, sar/dar, frame_rate, codec_name...
usage: m18.py <challenge> [start|retry|practice|none] [--submit] [--dir cached] [--save outdir] [--override id=value ...]
       (--run-for-time adds run_for_time:true to the start/retry body)"""
import sys, os, re, json, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import m15, m16, m17
from m15 import unzip_all, solve, map_ids, cj
from m16 import fix_json_kind
import media, video


def field_value(fld, b):
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
