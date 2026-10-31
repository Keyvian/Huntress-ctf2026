import sys, time, json, requests
sys.path.insert(0, "~/ctf")
from gm import GM

UA = {"User-Agent": "ctf-recon"}

def get(s, u, **kw):
    kw.setdefault("timeout", 12)
    try:
        return s.get(u, **kw)
    except Exception:
        return None

def wait_ready(url, limit=90):
    url = url.rstrip("/")
    t0 = time.time()
    while time.time() - t0 < limit:
        s = requests.Session(); s.headers.update(UA)
        try:
            r = s.get(url + "/", timeout=8)
            if r.status_code == 200 and "<" in r.text and "expired" not in r.text:
                return s, r
            if r.status_code in (408, 410) and "expired" in r.text:
                return None, "EXPIRED"
        except Exception:
            pass
        time.sleep(3)
    return None, None

def recon(base):
    g = GM()
    print("==== START", base, "====")
    r = g.start(base)
    if not r.get("targets"):
        r = g.retry(base)
    waited = 0
    while not r.get("targets") and waited < 60:
        time.sleep(4); waited += 4; r = g.status(base)
    print("questions:", json.dumps(r.get("questions"), indent=1)[:2000])
    for t in r.get("targets", []):
        url = t["url"]
        print("\n-- TARGET", t.get("id"), url)
        s, home = wait_ready(url)
        if not s:
            print("  not ready:", home); continue
        print("  HOME status", home.status_code, "len", len(home.text))
        print("  HOME HEAD:\n", home.text[:3000])
        for p in ("/api/clues", "/openapi.json", "/robots.txt"):
            rr = get(s, url.rstrip("/") + p)
            if rr is not None:
                print("  %s -> %s (len %d)" % (p, rr.status_code, len(rr.text)))
                if rr.status_code < 400:
                    print("   ", rr.text[:1500])

if __name__ == "__main__":
    recon(sys.argv[1])
