"""Day-9 script-analysis 'All the World's a Stager' solver (static decode only — never executes specimens).
usage: s9.py <challenge> --dir <cached start dir> [--show] [--submit [--only regex] [--exclude regex] [--chunk N]]
       answers persisted to <dir>/answers.json"""
import sys, os, io, re, json, time
sys.path.insert(0, "~/ctf")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pyzipper
from sdec import decode_specimen, parse_plan

STEM_ROLE = {"host-context": "benign_utility", "memory-stage": "stager", "embedded-write": "dropper",
             "remote-write": "downloader", "outbound-transfer": "uploader", "local-dispatch": "launcher",
             "impact-plan": "impact", "staged-handoff": "staged_chain", "relay-handoff": "staged_chain",  # graded
             "staged-chain": "staged_chain"}
ID_ROLE = {"benign": "benign_utility", "stager": "stager", "dropper": "dropper", "downloader": "downloader",
           "uploader": "uploader", "launcher": "launcher", "impact": "impact", "chain": "staged_chain",
           "relay": "relay", "persistence": "persistence_descriptor", "schedule": "persistence_descriptor"}
STEPS_ROLE = [
    ({"decode_configuration", "return_configuration"}, "benign_utility"),
    ({"acquire_remote", "dispatch_memory"}, "stager"), ({"acquire_remote", "dispatch_pipe"}, "stager"),
    ({"decode_embedded", "write_file"}, "dropper"),
    ({"acquire_remote", "write_file"}, "downloader"),
    ({"locate_local", "dispatch_process"}, "launcher"),
    ({"build_schedule", "register_descriptor"}, "persistence_descriptor"),
    ({"decode_configuration", "locate_interpreter", "dispatch_next_stage"}, "relay"),
]
EXEC_TECH = {"jscript": "T1059.007", "batch": "T1059.003", "vbscript": "T1059.005", "python": "T1059.006",
             "bash": "T1059.004", "nodejs": "T1059.007"}


def role_from_steps(steps):
    s = [x for x in steps if x]
    ss = set(s)
    for k, r in STEPS_ROLE:
        if ss == k:
            return r
    if {"transmit_remote"} & ss or {"upload_remote"} & ss:
        return "uploader"
    if "write_recovery_note" in ss or "transform_content" in ss or "transform_copy" in ss:
        return "impact"
    if "handoff_script" in ss or len(s) >= 4:
        return "staged_chain"
    return None


def attack_for(role, lang):
    return {"benign_utility": "none", "stager": "T1105", "downloader": "T1105", "dropper": "T1140",
            "uploader": "T1041", "impact": "T1486", "persistence_descriptor": "T1053.003",
            "advanced_syntax": "T1059.004"}.get(role, EXEC_TECH.get(lang, "T1059"))


# ---------------------------------------------------------------- style classifiers
def js_styles(s):
    m = re.search(r"(?m)^(?:var\s+(inspect_\w+)\s*=\s*function\s*(\w*)\s*\(|function\s+(inspect_\w+)\s*\()", s)
    if not m:
        return {}
    if m.group(3):
        fun = "declaration"
    elif m.group(2):
        fun = "named_expression"
    else:
        fun = "anonymous_expression"
    body = s[m.start():]
    e = re.search(r"(?m)^\};?\s*$", body)
    body = body[:e.end()] if e else body
    inv = "apply" if re.search(r"recover_\w+\.apply\s*\(", body) else "call" if re.search(r"recover_\w+\.call\s*\(", body) else "direct"
    dot = bool(re.search(r"\w\.(?:steps|adapter|values|stageCount)\b", body))
    br = bool(re.search(r"\[\s*[\"'](?:steps|adapter|values|stageCount)[\"']\s*\]", body))
    prop = "mixed" if dot and br else "bracket_literal" if br else "dot"
    return {"function-style": fun, "invocation-style": inv, "property-style": prop}


def batch_styles(s):
    region = s.split(":HUNTRESS_SEPARATOR_DONE", 1)[-1]
    region = region.split(":HUNTRESS_UNUSED", 1)[0].split(":HUNTRESS_PLAN", 1)[0]
    # Grader convention (Day 4 note, re-confirmed Day 9 single): '%%h<n>' in the recovery -> call_double;
    # FOR loop with 'do call set' -> for_indirect; everything else (incl. %%item0%% call-set, %x%, !x!) -> delayed.
    # (validated on 14 graded Day-9 specimens: TT outbound 'for .. do call set "cfg=%%cfg%%%%h%%G%%"' -> call_double;
    #  TT relay 'set "cfg=%h0%%h1%.."' (no CALL) -> delayed)
    if os.environ.get("S9_BATCH_LEGACY"):
        if any("%%h" in l for l in region.splitlines() if re.search(r"(?i)\bcall\s+set\b", l)):
            exp = "call_double"
        elif re.search(r"for\s+%%\w+\s+in\s*\([^)]*\)\s*do\s+call\s+set", region, re.I):
            exp = "for_indirect"
        else:
            exp = "delayed"
    else:
        # Day-15 TT grader: syntax-true expansion of the descriptor reconstruction statement
        # (8/9 legacy 'delayed' answers rejected; the one true !x! form accepted).
        exp = "delayed"
        for l in region.splitlines():
            if re.search(r"(?i)\bset\s+\"?neutral|HUNTRESS_READY=", l) or re.match(r"(?i)\s*echo", l):
                continue
            m = re.search(r"(?i)\bset\s+\"?\w+=(.*)$", l)
            if not m:
                continue
            val = m.group(1)
            if re.search(r"(?i)\bfor\s+%%\w+\s+in\s*\([^)]*\)\s*do\s+call\s+set", l):
                exp = "for_indirect"; break
            nref = len(re.findall(r"%%\w+%%|%\w+%|!\w+!", val))
            if nref < 2:
                continue
            if re.search(r"(?i)\bcall\s+set\b", l) and "%%" in val:
                exp = "call_double"
            elif re.search(r"!\w+!", val):
                exp = "delayed"
            else:
                exp = "percent"
            break
    if re.search(r"(?im)\bcall\s+:", region):
        ctrl = "call_subroutine"
    elif re.search(r"(?im)\bif\s+defined\b", region):
        ctrl = "if_guard"
    elif re.search(r"(?im)\bgoto\s+:", region):
        ctrl = "goto_dispatch"
    elif re.search(r"(?im)\bif\s+(?:not\s+)?errorlevel\b", region):
        ctrl = "errorlevel_guard"
    else:
        ctrl = "direct"
    return {"expansion": exp, "control": ctrl}


def vbs_control(s):
    m = re.search(r"(?ims)^Function\s+Recover_\w+\(\)(.*?)^End Function", s)
    if not m:
        return "direct"
    lines = [l.strip() for l in m.group(1).splitlines() if l.strip()]
    di = next((i for i, l in enumerate(lines) if re.search(r"Decode_\w+\(", l)), None)
    if di is None:
        return "direct"
    for l in reversed(lines[:di]):
        if re.match(r"(?i)Load_\w+|\w+\s*=\s*Load_", l):
            return "direct"
        if re.match(r"(?i)On Error Resume Next", l): return "error_guard"
        if re.match(r"(?i)(Select Case|Case\b)", l): return "select_case"
        if re.match(r"(?i)Do\b", l): return "do_once"
        if re.match(r"(?i)While\b", l): return "while_once"
        if re.match(r"(?i)For\b", l): return "for_once"
    return "direct"


# ---------------------------------------------------------------- per-question answering
SUFFIXES = ["function-style", "invocation-style", "property-style", "windows-chain", "stage-count", "host-profile",
            "stage-profile", "next-language", "next-stage", "user-agent", "upload-url", "file-path", "host-id",
            "note-name", "cron-path", "handoff-id", "role", "attack", "adapter", "campaign", "url", "path", "host",
            "extension", "note", "expansion", "control", "graph", "representation", "transform", "syntax",
            "obfuscation", "carrier", "steps", "feature", "primitive", "scenario", "wallet", "mutex", "file"]

KEYMAP = {"campaign": "campaign_id", "host-id": "host_id", "host": "host_id", "url": "url", "upload-url": "upload_url",
          "file-path": "file_path", "path": "file_path", "note-name": "note_name", "note": "note_name",
          "extension": "extension", "next-stage": "next_stage", "cron-path": "cron_path", "handoff-id": "handoff_id",
          "user-agent": "user_agent", "graph": "graph", "syntax": "syntax", "carrier": "carrier",
          "windows-chain": "windows_chain", "feature": "feature", "primitive": "primitive",
          "host-profile": "host_profile", "stage-profile": "stage_profile", "next-language": "next_language",
          "adapter": "adapter", "stage-count": "stage_count"}


def lang_of(fname, qid):
    q = qid.split(".", 1)[-1]
    for p, l in (("jscript-", "jscript"), ("batch-", "batch"), ("vbscript-", "vbscript"), ("python-", "python"),
                 ("bash-", "bash"), ("nodejs-", "nodejs"), ("polyglot-", "polyglot"), ("host-", "polyglot")):
        if q.startswith(p):
            return l
    if fname.endswith(".ps1"):
        return "ps1"
    return None


def flat_plan(dec):
    p = dict(dec.get("plan") or {})
    if isinstance(p.get("values"), dict):  # JScript JSON descriptor
        v = p.pop("values")
        p.update({k: v2 for k, v2 in v.items()})
        if "stageCount" in p:
            p["stage_count"] = p["stageCount"]
    if isinstance(p.get("steps"), list):
        p["steps"] = ",".join(p["steps"])
    return p


def answer(qid, fname, text, dec):
    q = qid.split(".", 1)[-1]
    suf = next((s for s in SUFFIXES if q.endswith("-" + s)), None)
    lang = lang_of(fname, qid)
    p = flat_plan(dec)
    stem = re.sub(r"\.(js|cmd|bat|vbs|ps1|py|sh|mjs|php|lua)$", "", fname)
    if lang == "ps1":
        d = dec.get("plan") or {}
        kind = stem.split("-")[0]
        if kind == "resource":
            v = {"scenario": "resource_hijacking", "attack": "T1496", "url": d.get("b"), "wallet": d.get("c"), "mutex": d.get("h")}
        elif kind == "collection":
            v = {"scenario": "synthetic_collection", "attack": "T1555.003", "url": d.get("b"),
                 "file": (d.get("c") or [None])[0] if isinstance(d.get("c"), list) else d.get("c"), "user-agent": d.get("f")}
        else:
            v = {"scenario": "synthetic_impact", "attack": "T1486", "extension": d.get("b"), "note": d.get("c"), "url": d.get("d")}
        return v.get(suf)
    # role
    if lang == "polyglot":
        role = p.get("role")
    elif q.startswith("bash-advanced"):
        role = "advanced_syntax"
    else:
        role = None
        if lang in ("jscript", "batch", "vbscript"):
            role = STEM_ROLE.get(stem)
        if role is None:
            mm = re.match(r"(?:python|bash|nodejs)-(.*)-[a-z-]+$", q)
            parts = (qid.split(".", 1)[-1]).split("-")
            for w in parts[1:]:
                if w in ID_ROLE:
                    role = ID_ROLE[w]; break
        if role is None:
            role = role_from_steps((p.get("steps") or "").split(","))
    if suf == "role":
        return role
    if suf == "attack":
        if lang == "polyglot":
            return p.get("attack")
        return attack_for(role, lang)
    if suf in ("function-style", "invocation-style", "property-style"):
        return js_styles(text).get(suf)
    if suf in ("expansion", "control") and lang == "batch":
        return batch_styles(text).get(suf)
    if suf == "control" and lang == "vbscript":
        return vbs_control(text)
    if suf == "representation":
        return dec.get("rep")
    if suf == "transform":
        return dec.get("xf")
    if suf == "obfuscation":
        return p.get("obfuscation_profile") if lang == "polyglot" else p.get("obfuscation")
    if suf == "steps":
        st = p.get("steps")
        return st.replace(",", ">") if st else None
    if suf == "url" and lang in ("jscript",) and role == "uploader":
        return p.get("url") or p.get("upload_url")
    if suf == "url" and not p.get("url") and p.get("upload_url"):
        return p.get("upload_url")
    # generic: longest id tail that names a plan key (schedule-path, service-name, registry-path, ...)
    toks = q.split("-")
    for i in range(1, len(toks)):
        key = "_".join(toks[i:])
        if key in p and suf not in ("adapter", "campaign", "role", "attack"):
            if suf in KEYMAP and KEYMAP[suf] in p and len(key) <= len(KEYMAP[suf]):
                break
            return str(p[key])
    if suf in KEYMAP:
        v = p.get(KEYMAP[suf])
        if v is None and suf == "note":
            v = p.get("note")
        return None if v is None else str(v)
    return None


def load(dd):
    st = json.load(open(os.path.join(dd, "start.json")))
    sets = {}
    for f in sorted(os.listdir(dd)):
        m = re.fullmatch(r"artifact(?:_d(\d+))?\.bin", f)
        if not m:
            continue
        k = int(m.group(1)) + 1 if m.group(1) else 1
        if k in sets:
            continue
        zf = pyzipper.AESZipFile(io.BytesIO(open(os.path.join(dd, f), "rb").read()))
        zf.setpassword(b"infected")
        files = {}
        for zi in zf.infolist():
            if zi.filename.endswith("/"):
                continue
            b = zf.read(zi.filename)
            if b[:2] == b"PK":  # nested per-set zip
                z2 = pyzipper.AESZipFile(io.BytesIO(b)); z2.setpassword(b"infected")
                mm = re.search(r"(\d+)\D*$", zi.filename)
                kk = int(mm.group(1)) if mm else len(sets) + 1
                sets[kk] = {os.path.basename(x.filename): z2.read(x.filename) for x in z2.infolist() if not x.filename.endswith("/")}
            else:
                files[os.path.basename(zi.filename)] = b
        if files:
            sets[k] = files
    return st, sets


def compute(st, sets):
    cache, ans, diag = {}, {}, []
    for q in st["questions"]:
        qid = q["id"]
        art = q.get("artifact") or ""
        fname = art.split("->")[-1].strip()
        sm = re.match(r"set(\d+)\.", qid)
        k = int(sm.group(1)) if sm else (q.get("set") or 1)
        files = sets.get(k) or sets.get(1)
        if fname not in files:
            diag.append((qid, "NOFILE", fname)); continue
        key = (k, fname)
        if key not in cache:
            t = files[fname].decode("utf-8-sig", "replace")
            cache[key] = (t, decode_specimen(fname, t))
        t, dec = cache[key]
        try:
            v = answer(qid, fname, t, dec)
        except Exception as e:
            v = None; diag.append((qid, "ERR", repr(e)))
        if v is None:
            diag.append((qid, "NONE", fname))
        else:
            ans[qid] = str(v)
    return ans, diag


def submit_chunks(ch, ans, ids, chunk=25, pause=1.6):
    from gm import GM
    g = GM()
    res = []
    for i in range(0, len(ids), chunk):
        sub = {k: ans[k] for k in ids[i:i + chunk]}
        for a in range(6):
            r = g.submit(ch, sub)
            if isinstance(r, dict) and (r.get("result") or r.get("flag")):
                break
            time.sleep(2 + 2 * a)
        res.append((ids[i:i + chunk], r.get("result"), r.get("remaining"), r.get("flag")))
        print("SUBMIT %d..%d -> %s rem=%s flag=%s err=%s" % (i, i + len(sub), r.get("result"), r.get("remaining"), r.get("flag"), r.get("error")), flush=True)
        if r.get("flag"):
            break
        time.sleep(pause)
    return res


if __name__ == "__main__":
    ch = sys.argv[1]
    dd = sys.argv[sys.argv.index("--dir") + 1]
    st, sets = load(dd)
    ans, diag = compute(st, sets)
    aids = st.get("answer_ids") or [q["id"] for q in st["questions"]]
    print("computed", len(ans), "/", len(aids), "unanswered", len(diag))
    for d in diag[:60]:
        print("  DIAG", d)
    json.dump(ans, open(os.path.join(dd, "answers.json"), "w"), indent=0)
    if "--show" in sys.argv:
        pat = sys.argv[sys.argv.index("--show") + 1] if len(sys.argv) > sys.argv.index("--show") + 1 and not sys.argv[sys.argv.index("--show") + 1].startswith("--") else ""
        for a in aids:
            if re.search(pat, a):
                print("  %-52s %s" % (a, ans.get(a, "<NONE>")[:150]))
    if "--submit" in sys.argv:
        ids = [a for a in aids if a in ans]
        if "--only" in sys.argv:
            pat = sys.argv[sys.argv.index("--only") + 1]
            ids = [a for a in ids if re.search(pat, a)]
        if "--exclude" in sys.argv:
            pat = sys.argv[sys.argv.index("--exclude") + 1]
            ids = [a for a in ids if not re.search(pat, a)]
        chunk = int(sys.argv[sys.argv.index("--chunk") + 1]) if "--chunk" in sys.argv else 25
        if "--by-file" in sys.argv:
            from gm import GM
            g = GM()
            art = {q["id"]: q.get("artifact", "") for q in st["questions"]}
            groups = {}
            for a in ids:
                sk = a.split(".")[0] + ":" if a.startswith("set") else ""
                groups.setdefault(sk + art[a], []).append(a)
            nf = int(sys.argv[sys.argv.index("--files") + 1]) if "--files" in sys.argv else 1
            keys = list(groups)
            batches = [keys[i:i + nf] for i in range(0, len(keys), nf)]

            def send(sub):
                for t in range(8):
                    r = g.submit(ch, sub)
                    if isinstance(r, dict) and (r.get("result") or r.get("flag")):
                        return r
                    time.sleep(2 + 2 * t)
                return r
            bad, flag = [], None
            for bk in batches:
                sub = {k: ans[k] for f in bk for k in groups[f]}
                r = send(sub)
                print("%-60s n=%-3d -> %s rem=%s flag=%s" % (bk[0][-60:], len(sub), r.get("result"), r.get("remaining"), r.get("flag")), flush=True)
                if r.get("flag"):
                    flag = r.get("flag"); break
                if r.get("result") == "incorrect":
                    if len(bk) == 1:
                        bad.append(bk[0])
                    else:
                        for f in bk:
                            time.sleep(1.6)
                            r2 = send({k: ans[k] for k in groups[f]})
                            print("   %-57s n=%-3d -> %s rem=%s flag=%s" % (f[-57:], len(groups[f]), r2.get("result"), r2.get("remaining"), r2.get("flag")), flush=True)
                            if r2.get("flag"):
                                flag = r2.get("flag"); break
                            if r2.get("result") == "incorrect":
                                bad.append(f)
                        if flag:
                            break
                time.sleep(1.6)
            print("BAD_GROUPS", bad, "FLAG", flag)
        else:
            submit_chunks(ch, ans, ids, chunk)
