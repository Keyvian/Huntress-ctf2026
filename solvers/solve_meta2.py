#!/usr/bin/env python3
"""General metadata-forensics solver (per-question property on real bytes).
Gathers every reachable file (default + deliveries, nested zips), resolves each
question's target member by zip/basename hint then content, and computes the
asked property: filename, size, md5/sha1/sha256/sha512, or first/last N bytes as
hex. Works for single_solve, time_trial, multi-set mastery; untrusted labels."""
import sys, re, json, io, zipfile, hashlib
import requests
GM="http://<homebase-ip>/huntress-ctf-proxy"
S=requests.Session(); S.headers.update({"Content-Type":"application/json"})
NOTE_SIGS=(b"Metadata Forensics",b"Case marker",b"Analyst",b"Endpoint",b"Huntress")
WORDNUM={"one":1,"two":2,"three":3,"four":4,"five":5,"six":6,"seven":7,"eight":8,
 "nine":9,"ten":10,"twelve":12,"sixteen":16,"twenty":20,"thirty-two":32,"four":4,
 "eight":8,"sixty-four":64,"thirty":30,"forty":40}

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
def gather(cid, need=1):
    # Fetch the default artifact FIRST (one request) and recurse nested zips.
    # Only probe delivery indices if the default did not already cover all sets.
    # (The mastery timer is short; minimising requests avoids crossing the
    # deadline mid-gather and desyncing questions from freshly-regenerated files.)
    out={}
    d=fetch(cid)
    if d[:2]==b"PK": extract_all(d,"",out)
    elif d and not is_err(d): out["raw#0"]=d
    if len(out) < need:
        for i in range(max(need,2)):
            r=fetch(cid,delivery=i)
            if not r or is_err(r): continue
            if r[:2]==b"PK": extract_all(r,"",out)
            else: out["raw#%d"%len(out)]=r
            if len(out) >= need: break
    return out
def base(p): return p.split(" -> ")[-1].split("/")[-1]
def parse_art(a):
    if not a: return None,None
    if "->" in a:
        l,r=a.rsplit("->",1); return l.strip(), r.strip().split("/")[-1]
    return a.strip(),None
def resolve(files,zip_name,hint,qid,setno=None):
    if not files: return None
    cands=list(files)                       # insertion order == archive/delivery order
    # 1) exact basename match (prefer the matching zip stem)
    if hint:
        exact=[p for p in cands if base(p)==hint]
        if zip_name:
            stem=base(zip_name).split(".zip")[0]
            pref=[p for p in exact if stem in p]
            if len(pref)==1: return pref[0]
        if len(exact)==1: return exact[0]
        if exact: return exact[0]
    # 2) positional by set index (labels are deceiving / renamed per attempt)
    if setno and 1<=setno<=len(cands):
        return cands[setno-1]
    # 3) content heuristic
    notes=[p for p in cands if any(s in files[p][:400] for s in NOTE_SIGS)]
    if zip_name:
        stem=base(zip_name).split(".zip")[0]
        z=[p for p in notes if stem in p]
        if z: return z[0]
    if notes: return notes[0]
    return cands[0] if len(cands)==1 else None
def numfrom(text):
    m=re.search(r"(\d+)",text)
    if m: return int(m.group(1))
    for w,n in WORDNUM.items():
        if w in text: return n
    return None
def compute(qid,qtext,data):
    low=(qid+" "+(qtext or "")).lower()
    # BOM / encoding determinations (BOM Voyage)
    if "bom" in low or "byte_order" in low or "byte order" in low:
        u8=data[:3]==b"\xef\xbb\xbf"; u16le=data[:2]==b"\xff\xfe"; u16be=data[:2]==b"\xfe\xff"
        if "utf8_bom_present" in low or ("utf8" in low and "bom" in low and "present" in low):
            return "true" if u8 else "false"
        if "utf16le" in low or ("utf-16le" in low): return "true" if u16le else "false"
        if "utf16be" in low or ("utf-16be" in low): return "true" if u16be else "false"
        if "bom_present" in low or ("bom" in low and "present" in low):
            return "true" if (u8 or u16le or u16be) else "false"
        if "encoding" in low or "byte_order" in low or "byte order" in low:
            return "utf-8" if u8 else "utf-16le" if u16le else "utf-16be" if u16be else "none"
    if "crlf" in low or ("line" in low and "ending" in low):
        return "true" if b"\r\n" in data else "false"
    if "filename" in low: return None  # set by caller
    if ("size" in low and "byte" in low) or low.endswith("-size-bytes"): return str(len(data))
    if "md5" in low: return hashlib.md5(data).hexdigest()
    if "sha1" in low or "sha-1" in low: return hashlib.sha1(data).hexdigest()
    if "sha256" in low or "sha-256" in low: return hashlib.sha256(data).hexdigest()
    if "sha512" in low or "sha-512" in low: return hashlib.sha512(data).hexdigest()
    if "hex" in low:
        m=re.search(r"hex-(\d+)", qid)           # trailing "...-hex-<N>"
        n=int(m.group(1)) if m else (numfrom(qtext or "") or 16)
        if "last" in low: return data[-n:].hex()
        return data[:n].hex()
    return None
def main():
    cid=sys.argv[1]; dry="dry" in sys.argv[2:]
    timed = "/time_trial" in cid or "/mastery" in cid
    st=start(cid)
    qs=st.get("questions") or []
    nsets=len({q.get("set") for q in qs if q.get("set")}) or len(qs) or 1
    files=gather(cid, need=nsets)
    hints=[parse_art(q.get("artifact"))[1] for q in qs]
    consistent=all(h is None or any(base(p)==h for p in files) for h in hints)
    answers={}
    for q in qs:
        qid=q["id"]; zip_name,hint=parse_art(q.get("artifact"))
        target=resolve(files,zip_name,hint,qid,q.get("set"))
        data=files.get(target,b"")
        val=compute(qid,q.get("question"),data)
        if val is None and "filename" in (qid+" "+(q.get("question") or "")).lower():
            val=base(target) if target else None
        answers[qid]=val
    print("### %s mode=%s deadline=%s consistent=%s files=%s"%(cid,st.get("mode"),st.get("deadline"),consistent,list(files)))
    print("    submit:",json.dumps(answers))
    if dry: print("DRY"); return
    if timed and not consistent:
        print("    SKIP: inconsistent attempt (asked file absent)"); sys.exit(3)
    res=S.post(GM,data=json.dumps({"op":"submit","challenge":cid,"answers":answers})).json()
    print("    RESULT:",json.dumps({k:res.get(k) for k in ("result","flag","status","remaining","accepted","error")}))
    sys.exit(0 if res.get("result")=="CORRECT" else 4)
main()
