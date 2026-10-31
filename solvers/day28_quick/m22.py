"""Day-22 metadata 'Main Character Energy' solver (any mode) = m21 (Day 1-21 cumulative contract incl. apk.*) + jar.<field>
for Java archives (jar.py: manifest parser + runnable / entry-point resolution + nested jars).
jar.main_class -> MANIFEST.MF Main-Class (graded CORRECT on single_solve: arena.evidence.ArtifactMain).
usage: m22.py <challenge> [start|retry|practice|none] [--submit] [--partial] [--dir cached] [--save outdir]
       [--override id=value ...] [--run-for-time]      offline: m22.py x none --dir <saved dir>"""
import sys, os, re, json, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import m15, m21, jar
from m15 import unzip_all, solve, map_ids
from m16 import fix_json_kind
from m20 import overrides
import apk


def field_value(fld, b):
    mo = re.fullmatch(r"(?:jar|java|archive)\.(\w+)", fld or "")
    if mo:
        return jar.field(b, mo.group(1))
    return m21.field_value(fld, b)


m15.field_value = field_value


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
        if p.lower().endswith(".jar") or (b[:2] == b"PK" and b"META-INF/MANIFEST.MF" in b and b"AndroidManifest.xml" not in b):
            try:
                i = jar.info(b)
                print("  JAR", p, len(b), "main", i["main_class"], "exists", i["main_class_exists"], "start", i["start_class"],
                      "launcher", i["is_launcher"], "entry", i["entry_point"], "runnable", i["runnable"],
                      "classes", i["class_count"], "nested", i["nested_jars"], "nested_main", i["nested_main"],
                      "manifest", i["manifest"])
            except Exception as ex:
                print("  JAR", p, "parse error", repr(ex))
    print("computed %d/%d in %.2fs; unknown %d" % (len(sub), len(st.get("answer_ids") or []), time.time() - t0, len(unk)))
    for k, v in list(sub.items())[:400]:
        if "jar" in k or "synthesis" in k or "UNK" in k:
            print("  %-70s %r" % (k, v))
    for u in unk:
        print("  UNK", u)
    if "--submit" in sys.argv and sub:
        if len(sub) != len(st.get("answer_ids") or []) and "--partial" not in sys.argv:
            print("ABORT submit: incomplete (use --partial to submit anyway)"); sys.exit(2)
        r = g.submit(ch, sub)
        print("SUBMIT", len(sub), {k: r.get(k) for k in ("result", "flag", "error", "remaining")}, "%.2fs" % (time.time() - t0))
