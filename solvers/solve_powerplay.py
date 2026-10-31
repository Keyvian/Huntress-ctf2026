#!/usr/bin/env python3
"""Solver for script-analysis-day-01 'Power Play' (native-signals).
Three password-protected (AES, pw 'infected') PowerShell specimens each hide a
Base64 JSON of indicators. Classify scenario, map primary ATT&CK technique, and
pull exact indicators. Works for single_solve/time_trial/mastery in one process."""
import sys, re, json, base64, io
import requests, pyzipper

GM = "http://<homebase-ip>/huntress-ctf-proxy"
S = requests.Session(); S.headers.update({"Content-Type": "application/json"})
ZIP_PW = b"infected"

ATTACK = {"resource_hijacking": "T1496", "synthetic_collection": "T1555.003", "synthetic_impact": "T1486"}


def is_err(b): return b[:1] == b"{" and b"error" in b[:60]


def start(cid):
    st = S.post(GM, data=json.dumps({"op": "start", "challenge": cid})).json()
    if st.get("answer_ids") is None or st.get("error"):
        rt = S.post(GM, data=json.dumps({"op": "retry", "challenge": cid})).json()
        if rt.get("answer_ids"):
            st = rt
    return st


def _open(blob):
    """Open a zip (plain or WinZip-AES) with pyzipper; return (zipobj, names)."""
    z = pyzipper.AESZipFile(io.BytesIO(blob)); z.setpassword(ZIP_PW)
    return z, z.namelist()


def _aes_group(blob):
    """Flat zip of .ps1 -> {ps1_basename: json_dict}."""
    g = {}
    try:
        z, names = _open(blob)
    except Exception:
        return g
    for n in names:
        if not n.lower().endswith(".ps1"):
            continue
        try:
            txt = z.read(n).decode("utf-8", "replace")
            m = re.search(r"FromBase64String\('([^']+)'\)", txt)
            if not m:
                continue
            g[n.split("/")[-1]] = json.loads(base64.b64decode(m.group(1)).decode("utf-8", "replace"))
        except Exception:
            continue
    return g


def _expand(blob):
    """Ordered list of groups {ps1: json}: a nested zip yields one group per
    inner zip (ordered by name); a flat zip yields one group."""
    try:
        z, names = _open(blob)
    except Exception:
        return []
    inner_zips = sorted(n for n in names if n.lower().endswith(".zip"))
    if inner_zips:
        out = []
        for n in inner_zips:
            try:
                g = _aes_group(z.read(n))
            except Exception:
                g = {}
            if g:
                out.append(g)
        return out
    g = _aes_group(blob)
    return [g] if g else []


def _num_sets(qs):
    s = set()
    for q in qs:
        m = re.match(r"set(\d+)\.", q["id"])
        s.add(int(m.group(1)) if m else 1)
    return max(s) if s else 1


def gather_groups(cid, need=1):
    """Ordered, de-duplicated groups; groups[i] = set i+1. Minimises requests:
    fetch default first; probe deliveries only until `need` sets are covered."""
    groups = []
    seen = set()

    def ingest(blob):
        if not blob or blob[:2] != b"PK":
            return
        for g in _expand(blob):
            key = frozenset(j.get("a") for j in g.values())
            if key and key not in seen:
                seen.add(key); groups.append(g)

    ingest(S.get(GM, params={"op": "artifact", "challenge": cid}).content)
    i = 0
    while len(groups) < need and i < max(need + 1, 3):
        d = S.get(GM, params={"op": "artifact", "challenge": cid, "delivery": i}).content
        if d and not is_err(d):
            ingest(d)
        i += 1
    return groups


def scenario_of(name, j):
    vals = [v for v in j.values() if isinstance(v, str)]
    allstr = " ".join(vals)
    if any("wallet" in v for v in vals):
        return "resource_hijacking"
    if any(v.startswith(".") for v in vals) and any(v.lower().endswith(".txt") for v in vals):
        return "synthetic_impact"
    # collection: browser data arrays / zip stage
    arrs = [v for v in j.values() if isinstance(v, list)]
    if arrs or any(v.lower().endswith(".zip") for v in vals):
        return "synthetic_collection"
    # fallback by filename
    n = name.lower()
    if "resource" in n: return "resource_hijacking"
    if "impact" in n: return "synthetic_impact"
    return "synthetic_collection"


def find_url(j):
    for v in j.values():
        if isinstance(v, str) and v.startswith("http"):
            return v
    return None


def find_where(j, pred):
    for v in j.values():
        if isinstance(v, str) and pred(v):
            return v
    return None


def first_filename(j):
    # first array element that looks like a filename, else first string ending .dat/.zip
    for v in j.values():
        if isinstance(v, list) and v:
            return v[0]
    for v in j.values():
        if isinstance(v, str) and re.search(r"\.(dat|zip|txt|exe|bin)$", v):
            return v
    return None


def parse_art(art):
    want_ps1 = None
    if art and "->" in art:
        want_ps1 = art.rsplit("->", 1)[1].strip().split("/")[-1]
    elif art:
        want_ps1 = art.strip().split("/")[-1]
    return want_ps1


def set_index(qid):
    m = re.match(r"set(\d+)\.", qid)
    return int(m.group(1)) - 1 if m else 0


def answer_for(q, groups, attack_map):
    qid = q["id"] if isinstance(q, dict) else q
    base = qid.split(".")[-1]            # strip set prefix
    prefix = base.split("-")[0]          # resource / collection / impact
    idx = set_index(qid)
    if idx >= len(groups):
        return None
    group = groups[idx]
    want_ps1 = parse_art(q.get("artifact") if isinstance(q, dict) else None) or (prefix + "-sample.ps1")
    j = group.get(want_ps1)
    name = want_ps1
    if j is None:  # fallback: match by sample prefix within the set
        for n, jj in group.items():
            if n.lower().startswith(prefix):
                name, j = n, jj
                break
    if j is None:
        return None
    scen = scenario_of(name, j)
    if base.endswith("scenario"):
        return scen
    if base.endswith("attack"):
        return attack_map.get(scen)
    if base.endswith("url"):
        return find_url(j)
    if base.endswith("wallet"):
        return find_where(j, lambda v: "wallet" in v)
    if base.endswith("mutex"):
        return find_where(j, lambda v: "Global\\" in v or v.startswith("Global\\"))
    if base.endswith("user-agent"):
        return find_where(j, lambda v: "Mozilla" in v or "/" in v and "Lab" in v)
    if base.endswith("extension"):
        return find_where(j, lambda v: v.startswith("."))
    if base.endswith("note"):
        return find_where(j, lambda v: v.lower().endswith(".txt"))
    if base.endswith("file"):
        return first_filename(j)
    return None


def main():
    cid = sys.argv[1]
    dry = "dry" in sys.argv[2:]
    attack_map = dict(ATTACK)
    # allow override: argv like collection=T1005
    for a in sys.argv[2:]:
        if a.startswith("synthetic_collection="):
            attack_map["synthetic_collection"] = a.split("=", 1)[1]
    st = start(cid)
    qs = st.get("questions") or []
    print("### %s mode=%s deadline=%s q=%d" % (cid, st.get("mode"), st.get("deadline"), len(qs)))
    need = _num_sets(qs)
    groups = gather_groups(cid, need=need)
    if len(groups) < need:  # timer likely expired mid-gather -> renew once and retry fast
        S.post(GM, data=json.dumps({"op": "retry", "challenge": cid}))
        st = start(cid); qs = st.get("questions") or qs
        groups = gather_groups(cid, need=need)
    print("need=%d groups=%s count=%d" % (need, [sorted(g) for g in groups], len(groups)))
    answers = {}
    for q in qs:
        answers[q["id"]] = answer_for(q, groups, attack_map)
    print(json.dumps(answers, indent=2, ensure_ascii=False))
    if dry:
        print("DRY"); return
    res = S.post(GM, data=json.dumps({"op": "submit", "challenge": cid, "answers": answers})).json()
    print("RESULT:", json.dumps({k: res.get(k) for k in ("result", "flag", "status", "remaining", "accepted", "incorrect", "message", "error", "detail")}, ensure_ascii=False))
    return res


if __name__ == "__main__":
    main()
