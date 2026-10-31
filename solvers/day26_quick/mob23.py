"""Day-23 mobile 'Hook Line and Signal' ("Separate real instrumentation signals from generated false positives."): mob20 +
NEW puzzle schema `huntress.mobile.puzzle.v2` with codec "analysis" and NO data field. The answer is what `Release.code(Context)`
in classes.dex computes: token() -> chain of 64-bit mixers (xor/mul/rotate with constants) + Probe.s2/s3 brute-force loops over
0..4095 whose results feed `instrumentationSignals()`; several "seal*" functions and K* constants are never called (the false
positives). We interpret the Dalvik bytecode in pure Python (dalvik.py) - nothing from the artifact is executed - and sanity
check the result against the ANS-<16 HEX> pattern. v1 codecs (plain/.../xor/caesar/indexed/native/dynamic) fall back to mob20.
usage: mob23.py <challenge> [--submit] [--retry|--practice] [--save dir] [--run-for-time] | mob23.py --local apk..."""
import sys, os, io, re, json, zipfile, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mob19, mob20, dalvik
from mob19 import ANS, apks_from

_orig_puzzle_answer = mob20.puzzle_answer


def analysis_answer(apk, z, p):
    r, vm = dalvik.answer(apk)  # whole APK: classes.dex + lib/<abi>/*.so for `native` methods (Day-15 jni_secret flavor)
    seen = []
    for t in vm.trace:
        if t not in seen: seen.append(t)
    print("  analysis: called", ", ".join("%s.%s" % (c.rsplit("/", 1)[-1].rstrip(";"), m) for c, m in seen), "steps", vm.steps)
    return r if isinstance(r, str) else "ANALYSIS?"


def puzzle_answer(apk):
    z = zipfile.ZipFile(io.BytesIO(apk))
    p = json.loads(z.read("assets/huntress_puzzle.json"))
    codec = (p.get("codec") or "").lower()
    if codec in ("analysis", "static", "compute", "code") or (p.get("schema", "").endswith(".v2") and "data" not in p):
        return analysis_answer(apk, z, p), p
    return _orig_puzzle_answer(apk)


if __name__ == "__main__":
    if sys.argv[1] == "--local":
        for f in sys.argv[2:]:
            for n, a in apks_from(open(f, "rb").read()):
                s, p = puzzle_answer(a)
                print(f, n, p.get("codec"), s, bool(ANS.fullmatch(s)))
        sys.exit(0)
    from gmx import GMX
    ch = sys.argv[1]
    t0 = time.time()
    g = GMX()
    op = "start"
    for o in ("retry", "practice"):
        if "--" + o in sys.argv: op = o
    body = {"op": op, "challenge": ch}
    if "--run-for-time" in sys.argv:
        body["run_for_time"] = True
    st = g.post(body)
    aids = st.get("answer_ids") or []
    print("mode", st.get("mode"), "deadline", st.get("deadline"), "uar", st.get("unique_attempts_remaining"), "ids", aids)
    if not aids:
        print({k: v for k, v in st.items() if k != "guidance"}); sys.exit(1)
    raw0 = g.artifact(ch)
    sd = None
    if "--save" in sys.argv:
        sd = sys.argv[sys.argv.index("--save") + 1]; os.makedirs(sd, exist_ok=True)
        json.dump(st, open(os.path.join(sd, "start.json"), "w"))
        open(os.path.join(sd, "artifact.bin"), "wb").write(raw0)
    apks = apks_from(raw0)
    if len(apks) < len(aids):
        for d in range(1, len(aids)):
            try:
                b = g.artifact(ch, d)
                if sd:
                    open(os.path.join(sd, "artifact%d.bin" % d), "wb").write(b)
                apks += apks_from(b)
            except Exception as e:
                print("delivery", d, "ERR", e)
    ans = {}
    for i, a in enumerate(aids):
        s, p = puzzle_answer(apks[min(i, len(apks) - 1)][1])
        print(a, apks[min(i, len(apks) - 1)][0], p.get("schema"), p.get("codec"), s)
        ans[a] = s
    print("compute %.2fs" % (time.time() - t0))
    if not all(ANS.fullmatch(v) for v in ans.values()):
        print("ABORT: not all answers match ANS pattern"); sys.exit(2)
    if "--submit" in sys.argv:
        r = g.submit(ch, ans)
        print("SUBMIT", {k: r.get(k) for k in ("result", "flag", "error", "remaining")}, "%.2fs" % (time.time() - t0))
