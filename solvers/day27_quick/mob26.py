"""Day-26 mobile 'Split Decision' ("Reassemble evidence distributed across base and configuration splits."): mob23 + NEW
puzzle v1 codec "split" delivered as an .apks bundle (zip of APKs). base.apk assets/huntress_puzzle.json =
{"schema":"huntress.mobile.puzzle.v1","codec":"split","data":"","parts":["", "ANS-7", "E37D13"],"order":[2,0,1]} with some
parts blank; each configuration/feature split carries assets/huntress_feature.json {"codec":"split","part":"4754DEA01",
"part_index":0} that fills parts[part_index]. Reassembly convention: output slot order[i] <- parts[i] (the other reading,
parts[order[k]], is also tried; the ANS-<16 HEX> pattern picks the valid one). The dex only builds the unreachable backend URL
(red herring) - nothing from the artifact is executed. Non-split puzzles fall back to mob23 (v2 analysis / v1 codecs).
usage: mob26.py <challenge> [--submit] [--retry|--practice] [--save dir] [--run-for-time] | mob26.py --local file..."""
import sys, os, io, json, zipfile, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mob23, dalvik
from mob19 import ANS
try:
    import apk as apkmod
except Exception:  # pragma: no cover
    apkmod = None


def install_name(n, b):
    """installed file name of one split: base.apk for the puzzle carrier, split_<splitName>.apk for a configuration/feature
    split (name from the binary AndroidManifest `split` attribute), else the bundle member's basename."""
    try:
        names = zipfile.ZipFile(io.BytesIO(b)).namelist()
    except Exception:
        names = []
    if "assets/huntress_puzzle.json" in names or "classes.dex" in names and n.split("/")[-1].startswith("base"):
        return "base.apk"
    sn = None
    if apkmod is not None:
        try:
            m = apkmod.manifest(b)
            if isinstance(m, dict):
                sn = m.get("split") or (m.get("manifest") or {}).get("split") if isinstance(m.get("manifest"), dict) else m.get("split")
        except Exception:
            sn = None
        if not sn:
            try:
                for el in apkmod.axml(zipfile.ZipFile(io.BytesIO(b)).read("AndroidManifest.xml")):
                    at = el.get("attrs") if isinstance(el, dict) else None
                    if isinstance(at, dict) and at.get("split"):
                        sn = at["split"]; break
            except Exception:
                sn = None
    return ("split_%s.apk" % sn) if sn else n.split(":")[-1].split("/")[-1]


def analysis_answer(apks, base):
    """v2 'analysis' puzzle inside a split bundle: interpret Release.code(Context) with the WHOLE split set visible to the VM
    (Day 26 reads assets/huntress_feature.bin out of the feature split via ApplicationInfo.splitSourceDirs + ZipFile)."""
    splits = [(install_name(n, b), b) for n, b in apks]
    r, vm = dalvik.answer(base[1], splits=splits)
    seen = []
    for t in vm.trace:
        if t not in seen: seen.append(t)
    print("  analysis: splits", [s for s, _ in splits], "called", ", ".join("%s.%s" % (c.rsplit("/", 1)[-1].rstrip(";"), m) for c, m in seen), "steps", vm.steps)
    return r if isinstance(r, str) else "ANALYSIS?"


def is_apk(b):
    try:
        return "AndroidManifest.xml" in zipfile.ZipFile(io.BytesIO(b)).namelist()
    except Exception:
        return False


def bundles_from(raw, label=""):
    """[(label, [(name, apk_bytes), ...])]: a bare APK is one bundle; an .apks (zip of APKs) is one bundle; a zip of .apks (or of
    APKs in sub-folders) yields one bundle per inner .apks."""
    if is_apk(raw):
        return [(label or "apk", [(label or "apk", raw)])]
    try:
        z = zipfile.ZipFile(io.BytesIO(raw))
    except Exception:
        return []
    members = [(n, z.read(n)) for n in z.namelist() if not n.endswith("/")]
    apks = [(n, b) for n, b in members if b[:2] == b"PK" and is_apk(b)]
    if apks:
        return [(label or "bundle", apks)]
    out = []
    for n, b in members:
        if b[:2] == b"PK":
            out += bundles_from(b, (label + ":" if label else "") + n)
    return out


def split_answer(apks):
    """codec 'split': gather parts from the base puzzle + every split's assets/*.json carrying part/part_index, reassemble."""
    base = None
    feats = []
    for n, b in apks:
        z = zipfile.ZipFile(io.BytesIO(b))
        names = z.namelist()
        if "assets/huntress_puzzle.json" in names:
            base = (n, b, json.loads(z.read("assets/huntress_puzzle.json")))
        for m in names:
            if m.startswith("assets/") and m.endswith(".json") and m != "assets/huntress_puzzle.json":
                try:
                    j = json.loads(z.read(m))
                except Exception:
                    continue
                if isinstance(j, dict) and "part" in j:
                    feats.append((n, m, j))
    if base is None:
        return None, {}
    p = base[2]
    codec = (p.get("codec") or "").lower()
    if codec != "split":
        if codec in ("analysis", "static", "compute", "code") or (p.get("schema", "").endswith(".v2") and "data" not in p):
            return analysis_answer(apks, base), p
        s, p2 = mob23.puzzle_answer(base[1])
        return s, p2
    parts = list(p.get("parts") or [])
    for n, m, j in feats:
        idx = j.get("part_index", j.get("index"))
        if idx is None:
            continue
        while len(parts) <= idx:
            parts.append("")
        if not parts[idx]:
            parts[idx] = str(j["part"])
        elif parts[idx] != j["part"]:
            print("  WARN part", idx, "conflict", parts[idx], "vs", j["part"], "from", n, m)
    if p.get("data"):
        print("  NOTE data field non-empty:", p["data"][:80])
    order = p.get("order") or list(range(len(parts)))
    slots = [""] * max(len(parts), len(order))
    for i, o in enumerate(order):
        if i < len(parts):
            slots[o] = parts[i]
    cands = [("slot[order[i]]=parts[i]", "".join(slots)),
             ("parts[order[k]]", "".join(parts[o] for o in order if o < len(parts))),
             ("concat", "".join(parts))]
    print("  split: parts", parts, "order", order, "feats", [(n.split(":")[-1], j.get("part_index")) for n, m, j in feats])
    for lab, s in cands:
        if ANS.fullmatch(s):
            print("  split: convention", lab, "->", s)
            return s, p
    print("  split: NO candidate matches ANS pattern:", cands)
    return cands[0][1], p


if __name__ == "__main__":
    if sys.argv[1] == "--local":
        for f in sys.argv[2:]:
            for lab, apks in bundles_from(open(f, "rb").read()):
                s, p = split_answer(apks)
                print(f, lab, [n for n, _ in apks], p.get("codec"), s, bool(ANS.fullmatch(s or "")))
        sys.exit(0)
    from gmx import GMX
    ch = sys.argv[1]
    t0 = time.time()
    g = GMX()
    op = "start"
    for o in ("retry", "practice"):
        if "--" + o in sys.argv:
            op = o
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
    bundles = bundles_from(raw0)
    if len(bundles) < len(aids):
        for d in range(1, len(aids)):
            try:
                b = g.artifact(ch, d)
                if b[:1] == b"{" and len(b) < 400:
                    print("delivery", d, b); continue
                if sd:
                    open(os.path.join(sd, "artifact%d.bin" % d), "wb").write(b)
                bundles += bundles_from(b, "delivery%d" % d)
            except Exception as e:
                print("delivery", d, "ERR", e)
    print("bundles", len(bundles), [(l, [n for n, _ in a]) for l, a in bundles][:12], "%.2fs" % (time.time() - t0))
    ans = {}
    for i, a in enumerate(aids):
        lab, apks = bundles[min(i, len(bundles) - 1)]
        s, p = split_answer(apks)
        print(a, lab, p.get("schema"), p.get("codec"), s)
        ans[a] = s or ""
    print("compute %.2fs" % (time.time() - t0))
    if not all(ANS.fullmatch(v) for v in ans.values()):
        print("ABORT: not all answers match ANS pattern"); sys.exit(2)
    if "--submit" in sys.argv:
        r = g.submit(ch, ans)
        print("SUBMIT", {k: r.get(k) for k in ("result", "flag", "error", "remaining")}, "%.2fs" % (time.time() - t0))
