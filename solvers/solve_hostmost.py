#!/usr/bin/env python3
"""Solver for script-analysis-day-02 'Host With the Most' (encoded-intent).
PowerShell trio (as day-01) + eight WSH JScript specimens that eval-reconstruct a
JSON plan. Node runs each specimen's own inspect() to recover the plan
deterministically; JS text is parsed for the syntax-style questions. The untimed
single_solve uses the GM's partial 'remaining' feedback to pin uncertain ATT&CK
IDs; learned maps are reused for the timed modes."""
import sys, re, json, io, os, base64, subprocess, tempfile
import requests, pyzipper

GM = "http://<homebase-ip>/huntress-ctf-proxy"
S = requests.Session(); S.headers.update({"Content-Type": "application/json"})
ZIP_PW = b"infected"
NODE_DRIVER = "/tmp/hm_decode.js"

PS_ATTACK = {"resource_hijacking": "T1496", "synthetic_collection": "T1555.003", "synthetic_impact": "T1486"}

ROLE_ENUM = {"benign": "benign_utility", "stager": "stager", "dropper": "dropper",
             "downloader": "downloader", "launcher": "launcher", "chain": "staged_chain",
             "uploader": "uploader", "impact": "impact", "relay": "staged_chain"}

# ATT&CK per JScript role (confirmed via single_solve partial-feedback probing):
# JScript execution is the primary technique for launchers/chains; acquisition =>
# T1105, decode+write dropper => T1140, upload => T1041, impact => T1486.
JS_ATTACK = {"benign_utility": "none", "stager": "T1105", "dropper": "T1140",
             "downloader": "T1105", "staged_chain": "T1059.007",
             "launcher": "T1059.007", "uploader": "T1041", "impact": "T1486"}


def is_err(b): return b[:1] == b"{" and b"error" in b[:60]


def start(cid):
    st = S.post(GM, data=json.dumps({"op": "start", "challenge": cid})).json()
    if st.get("answer_ids") is None or st.get("error"):
        rt = S.post(GM, data=json.dumps({"op": "retry", "challenge": cid})).json()
        if rt.get("answer_ids"):
            st = rt
    return st


def submit(cid, answers):
    return S.post(GM, data=json.dumps({"op": "submit", "challenge": cid, "answers": answers})).json()


def _open(blob):
    z = pyzipper.AESZipFile(io.BytesIO(blob)); z.setpassword(ZIP_PW)
    return z, z.namelist()


def ps_json(txt):
    m = re.search(r"FromBase64String\('([^']+)'\)", txt)
    if not m:
        return None
    try:
        return json.loads(base64.b64decode(m.group(1)).decode("utf-8", "replace"))
    except Exception:
        return None


NODE_DIR_DRIVER = "/tmp/hm_decode_dir.js"


def node_plans(js_files):
    """Batch-decode {basename: js_bytes} via ONE node call -> {basename: plan}."""
    if not js_files:
        return {}
    d = tempfile.mkdtemp(dir="/tmp")
    for bn, data in js_files.items():
        with open(os.path.join(d, bn), "wb") as f:
            f.write(data)
    try:
        out = subprocess.run(["node", NODE_DIR_DRIVER, d], capture_output=True, text=True, timeout=30)
        return json.loads(out.stdout)
    except Exception:
        return {}


# ---- JS syntax-style parsing ----
def _inspect_body(js):
    m = re.search(r"inspect_[0-9a-fA-F]+", js)
    if not m:
        return "", None
    name = m.group(0)
    i = js.find(name)
    b = js.find("{", i)
    depth = 0
    for k in range(b, len(js)):
        if js[k] == "{": depth += 1
        elif js[k] == "}":
            depth -= 1
            if depth == 0:
                return js[b:k + 1], name
    return js[b:], name


def func_style(js, name):
    if re.search(r"function\s+" + re.escape(name) + r"\s*\(", js):
        return "declaration"
    m = re.search(r"\b" + re.escape(name) + r"\s*=\s*function\s*([A-Za-z0-9_]*)\s*\(", js)
    if m:
        return "named_expression" if m.group(1) else "anonymous_expression"
    return None


def invoke_style(body):
    if re.search(r"recover_[0-9a-fA-F]+\s*\.\s*apply\s*\(", body):
        return "apply"
    if re.search(r"recover_[0-9a-fA-F]+\s*\.\s*call\s*\(", body):
        return "call"
    if re.search(r"recover_[0-9a-fA-F]+\s*\(", body):
        return "direct"
    return None


def prop_style(body):
    # How the reconstructed descriptor (the eval() result var) is read: dot vs bracket.
    m = re.search(r"var\s+(\w+)\s*=\s*eval\s*\(", body)
    if not m:
        return None
    var = re.escape(m.group(1))
    dot = bool(re.search(var + r"\s*\.\s*[A-Za-z_]\w*", body))
    brk = bool(re.search(var + r"\s*\[\s*\"", body))
    if dot and brk:
        return "mixed"
    if dot:
        return "dot"
    if brk:
        return "bracket_literal"
    return None


# ---- gather ----
def _expand(blob):
    try:
        z, names = _open(blob)
    except Exception:
        return []
    inner = sorted(n for n in names if n.lower().endswith(".zip"))
    if inner:
        out = []
        for n in inner:
            try:
                g = _group(z.read(n))
            except Exception:
                g = {}
            if g:
                out.append(g)
        return out
    g = _group(blob)
    return [g] if g else []


def _group(blob):
    """Return {basename: ('ps1'|'js', payload)}; JS plans decoded in one node call."""
    g = {}
    try:
        z, names = _open(blob)
    except Exception:
        return g
    js_bytes = {}
    js_text = {}
    for n in names:
        bn = n.split("/")[-1]
        try:
            data = z.read(n)
        except Exception:
            continue
        if bn.lower().endswith(".ps1"):
            j = ps_json(data.decode("utf-8", "replace"))
            if j is not None:
                g[bn] = ("ps1", j)
        elif bn.lower().endswith(".js"):
            js_bytes[bn] = data
            js_text[bn] = data.decode("utf-8", "replace")
    plans = node_plans(js_bytes)
    for bn in js_bytes:
        g[bn] = ("js", {"plan": plans.get(bn), "text": js_text[bn]})
    return g


def _num_sets(qs):
    s = {int(m.group(1)) for q in qs for m in [re.match(r"set(\d+)\.", q["id"])] if m}
    return max(s) if s else 1


def _content_key(g):
    """Per-set content signature (campaign ids + ps1 ids) — distinguishes sets
    even though filenames repeat across sets."""
    ids = set()
    for bn, (kind, payload) in g.items():
        if kind == "ps1":
            ids.add(payload.get("a"))
        else:
            plan = payload.get("plan") or {}
            ids.add((plan.get("values") or {}).get("campaign_id"))
    return frozenset(x for x in ids if x)


def gather(cid, need=1):
    groups, seen, seen_blob = [], set(), set()

    def ingest(blob):
        if not blob or blob[:2] != b"PK":
            return
        import hashlib
        h = hashlib.sha256(blob).hexdigest()
        if h in seen_blob:
            return
        seen_blob.add(h)
        for g in _expand(blob):
            key = _content_key(g)
            if key and key not in seen:
                seen.add(key); groups.append(g)

    ingest(S.get(GM, params={"op": "artifact", "challenge": cid}).content)
    i = 0
    while len(groups) < need and i < max(need + 2, 4):
        d = S.get(GM, params={"op": "artifact", "challenge": cid, "delivery": i}).content
        if d and not is_err(d):
            ingest(d)
        i += 1
    return groups


# ---- answer building ----
def set_index(qid):
    m = re.match(r"set(\d+)\.", qid)
    return int(m.group(1)) - 1 if m else 0


def ps_answer(base, j):
    prefix = base.split("-")[0]
    scen = {"resource": "resource_hijacking", "collection": "synthetic_collection",
            "impact": "synthetic_impact"}[prefix]
    vals = [v for v in j.values() if isinstance(v, str)]
    if base.endswith("scenario"): return scen
    if base.endswith("attack"): return PS_ATTACK[scen]
    if base.endswith("url"): return next((v for v in j.values() if isinstance(v, str) and v.startswith("http")), None)
    if base.endswith("wallet"): return next((v for v in vals if "wallet" in v), None)
    if base.endswith("mutex"): return next((v for v in vals if "Global\\" in v), None)
    if base.endswith("user-agent"): return next((v for v in vals if "Mozilla" in v), None)
    if base.endswith("extension"): return next((v for v in vals if v.startswith(".")), None)
    if base.endswith("note"): return next((v for v in vals if v.lower().endswith(".txt")), None)
    if base.endswith("file"):
        for v in j.values():
            if isinstance(v, list) and v: return v[0]
        return next((v for v in vals if re.search(r"\.(dat|zip|txt)$", v)), None)
    return None


def js_answer(base, rolekey, plan, text):
    role = ROLE_ENUM.get(rolekey)
    v = (plan or {}).get("values", {})
    if base.endswith("-role") or base == rolekey + "-role" or base.endswith("role"):
        return role
    if base.endswith("attack"):
        return JS_ATTACK.get(role)
    if base.endswith("adapter"): return (plan or {}).get("adapter")
    if base.endswith("campaign"): return v.get("campaign_id")
    if base.endswith("host"): return v.get("host_id")
    if base.endswith("url"): return v.get("url")
    if base.endswith("path"): return v.get("file_path")
    if base.endswith("next-stage"): return v.get("next_stage")
    if base.endswith("extension"): return v.get("extension")
    if base.endswith("note"): return v.get("note_name")
    body, insp = _inspect_body(text)
    if base.endswith("function-style"): return func_style(text, insp) if insp else None
    if base.endswith("invocation-style"): return invoke_style(body)
    if base.endswith("property-style"): return prop_style(body)
    return None


def artifact_basename(q):
    a = q.get("artifact") or ""
    return a.rsplit("->", 1)[-1].strip().split("/")[-1] if a else ""


def build_answers(qs, groups):
    answers = {}
    for q in qs:
        qid = q["id"]; base = qid.split(".")[-1]
        idx = set_index(qid)
        if idx >= len(groups):
            answers[qid] = None; continue
        group = groups[idx]
        bn = artifact_basename(q)
        kind_payload = group.get(bn)
        if kind_payload is None:  # fallback by prefix
            if base.startswith("jscript-"):
                rk = base.split("-")[1]
                want = {"benign": "host-context", "stager": "memory-stage", "dropper": "embedded-write",
                        "downloader": "remote-write", "launcher": "local-dispatch", "chain": "staged-handoff",
                        "uploader": "outbound-transfer", "impact": "impact-plan", "relay": "relay-handoff"}.get(rk)
                for k, vv in group.items():
                    if want and want in k: kind_payload = vv; break
            else:
                pfx = base.split("-")[0]
                for k, vv in group.items():
                    if k.startswith(pfx) and vv[0] == "ps1": kind_payload = vv; break
        if kind_payload is None:
            answers[qid] = None; continue
        kind, payload = kind_payload
        if kind == "ps1":
            answers[qid] = ps_answer(base, payload)
        else:
            rk = base.split("-")[1] if base.startswith("jscript-") else None
            answers[qid] = js_answer(base, rk, payload.get("plan"), payload.get("text"))
    return answers


def main():
    cid = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 else "oneshot"
    st = start(cid)
    qs = st.get("questions") or []
    need = _num_sets(qs)
    groups = gather(cid, need=need)
    if len(groups) < need:
        S.post(GM, data=json.dumps({"op": "retry", "challenge": cid}))
        st = start(cid); qs = st.get("questions") or qs
        groups = gather(cid, need=need)
    answers = build_answers(qs, groups)
    none_ids = [k for k, v in answers.items() if v is None]
    print("### %s mode=%s q=%d groups=%d none=%d" % (cid, st.get("mode"), len(qs), len(groups), len(none_ids)))
    if none_ids:
        print("NONE ids:", none_ids[:20])

    def is_uncertain(qid):
        base = qid.split(".")[-1]
        if not (base.startswith("jscript-") and base.endswith("attack")):
            return False
        return ROLE_ENUM.get(base.split("-")[1]) in (
            "stager", "dropper", "downloader", "uploader", "staged_chain", "relay")

    if mode == "learn":
        cand = {
            "uploader": ["T1041", "T1567", "T1048", "T1567.002", "T1020", "T1105", "T1071"],
            "staged_chain": ["T1105", "T1059.001", "T1059.007", "T1059", "T1106", "T1204"],
            "relay": ["T1105", "T1059.007", "T1059.001", "T1059", "T1106", "T1204"],
            "stager": ["T1105", "T1059.007", "T1059", "T1106", "T1027"],
            "dropper": ["T1105", "T1059.007", "T1059", "T1140", "T1027"],
            "downloader": ["T1105", "T1059.007", "T1059", "T1071"],
        }
        confident = {k: v for k, v in answers.items() if not is_uncertain(k)}
        r = submit(cid, confident)
        print("confident batch:", json.dumps({k: r.get(k) for k in ("result", "remaining", "error")}))
        if r.get("result") == "incorrect":
            print("A confident answer is wrong — needs debugging; aborting learn.")
            return r
        for q in qs:
            if not is_uncertain(q["id"]):
                continue
            role = ROLE_ENUM.get(q["id"].split(".")[-1].split("-")[1])
            got = None
            for c in cand.get(role, []):
                rr = submit(cid, {q["id"]: c})
                if rr.get("result") in ("accepted", "CORRECT"):
                    got = c; JS_ATTACK[role] = c
                    print("LEARN %s=%s (rem=%s)" % (q["id"], c, rr.get("remaining")))
                    if rr.get("result") == "CORRECT":
                        print("FLAG", rr.get("flag")); return rr
                    break
            if got is None:
                print("LEARN %s: NO candidate worked" % q["id"])
        print("JS_ATTACK learned:", {k: JS_ATTACK[k] for k in ("stager","dropper","downloader","uploader","staged_chain","relay")})
        res = submit(cid, build_answers(qs, groups))
        print("final submit:", json.dumps({k: res.get(k) for k in ("result", "flag", "remaining")}))
        return res

    res = submit(cid, answers)
    print("submit-all:", json.dumps({k: res.get(k) for k in ("result", "flag", "remaining", "status", "error")}))
    if res.get("result") == "CORRECT":
        print("FLAG", res.get("flag"))
    return res


if __name__ == "__main__":
    main()
