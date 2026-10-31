#!/usr/bin/env python3
"""Universal warmup solver: decode an assigned blob (Base64 / ROT13 / Base32 /
hex, possibly layered or index-prefixed) and submit the answer slug named in the
final decoded line ("...submit this exact answer to the Game Master: <slug>").
Handles single_solve, time_trial, and multi-blob mastery in one process."""
import sys, re, json, io, zipfile, base64, codecs, binascii
import requests
GM="http://<homebase-ip>/huntress-ctf-proxy"
S=requests.Session(); S.headers.update({"Content-Type":"application/json"})
SLUG=re.compile(r"[a-z]+-[a-z]+-[a-z]+-\d{2}")
IDX=re.compile(r"^\s*\d+[\t ]+(.*)$", re.S)

def start(cid):
    st=S.post(GM,data=json.dumps({"op":"start","challenge":cid})).json()
    if st.get("answer_ids") is None or st.get("error"):
        rt=S.post(GM,data=json.dumps({"op":"retry","challenge":cid})).json()
        if rt.get("answer_ids"): st=rt
    return st

def fetch(cid,delivery=None):
    p={"op":"artifact","challenge":cid}
    if delivery is not None: p["delivery"]=delivery
    return S.get(GM,params=p).content

def is_err(b): return b[:1]==b"{" and b"error" in b[:60]

def extract_all(blob,prefix,out):
    if blob[:2]!=b"PK": return
    try: z=zipfile.ZipFile(io.BytesIO(blob))
    except: return
    for info in z.infolist():
        try: b=z.read(info.filename)
        except: continue
        p=prefix+info.filename
        if info.filename.lower().endswith(".zip") and b[:2]==b"PK": extract_all(b,p+" -> ",out)
        else: out[p]=b

def gather(cid):
    out={}; blobs=[fetch(cid)]
    for i in range(10):
        d=fetch(cid,delivery=i)
        if d and not is_err(d): blobs.append(d)
    for b in blobs:
        if b[:2]==b"PK": extract_all(b,"",out)
        elif b and not is_err(b): out["blob#%d"%len(out)]=b
    return out

def transforms(s):
    yield s
    try: yield codecs.decode(s,"rot_13")
    except: pass
    for pad in range(4):
        try:
            d=base64.b64decode(s+"="*pad,validate=False).decode("utf-8","replace")
            if d: yield d; 
            try: yield codecs.decode(d,"rot_13")
            except: pass
        except: pass
        break
    try: yield base64.b32decode(s+"="*((8-len(s)%8)%8)).decode("utf-8","replace")
    except: pass
    try: yield binascii.unhexlify(re.sub(r"\s","",s)).decode("utf-8","replace")
    except: pass

def find_slug(raw):
    text=raw.decode("utf-8","replace")
    lines=[l for l in text.splitlines() if l.strip()] or [text]
    cand=lines[-1]
    m=IDX.match(cand)
    payload=m.group(1) if m else cand
    seen=set(); frontier=[payload, text]
    for _ in range(3):
        nxt=[]
        for s in frontier:
            for t in transforms(s):
                if t in seen: continue
                seen.add(t)
                mm=SLUG.search(t)
                if mm and ("Game Master" in t or "submit" in t.lower()):
                    return mm.group(0)
                nxt.append(t)
        frontier=nxt
    # fallback: any slug anywhere
    for s in seen:
        mm=SLUG.search(s)
        if mm: return mm.group(0)
    return None

def main():
    cid=sys.argv[1]; dry="dry" in sys.argv[2:]
    st=start(cid); qs=st.get("questions") or []
    print("### %s mode=%s deadline=%s q=%d"%(cid,st.get("mode"),st.get("deadline"),len(qs)))
    files=gather(cid)
    answers={}
    for q in qs:
        qid=q["id"]; art=q.get("artifact") or ""
        hint=art.split("->")[-1].strip().split("/")[-1] if "->" in art else art.strip()
        # pick file: match basename hint, else any blob
        target=None
        for p in files:
            if p.split(" -> ")[-1].split("/")[-1]==hint: target=p; break
        if target is None:
            # mastery: blobs named blob-01.txt etc.; match by set index
            setno=q.get("set")
            cands=sorted(files)
            if setno and setno-1 < len(cands): target=cands[setno-1]
            elif cands: target=cands[0]
        slug=find_slug(files.get(target,b""))
        print("  q=%s set=%s target=%r -> slug=%s"%(qid,q.get("set"),target,slug))
        answers[qid]=slug
    print("### submit:",json.dumps(answers))
    if dry: print("DRY"); return
    res=S.post(GM,data=json.dumps({"op":"submit","challenge":cid,"answers":answers})).json()
    print("### RESULT:",json.dumps({k:res.get(k) for k in ("result","flag","status","remaining","accepted","error")}))
main()
