#!/usr/bin/env python3
"""Day3 mobile 'Intent Injection': answer is assets/huntress_puzzle.json
{schema,day,codec,data} -> decode data by codec. Handles single/time_trial/
multi-set mastery (set K -> delivery K-1). One fast process per attempt."""
import sys, json, io, zipfile, base64, binascii, codecs, gzip
import requests
GM="http://<homebase-ip>/huntress-ctf-proxy"
S=requests.Session(); S.headers.update({"Content-Type":"application/json"})

def start(cid):
    st=S.post(GM,data=json.dumps({"op":"start","challenge":cid})).json()
    if st.get("answer_ids") is None or st.get("error"):
        rt=S.post(GM,data=json.dumps({"op":"retry","challenge":cid})).json()
        if rt.get("answer_ids"): st=rt
    return st
def fetch(cid,d=None):
    p={"op":"artifact","challenge":cid}
    if d is not None: p["delivery"]=d
    return S.get(GM,params=p).content
def is_err(b): return b[:1]==b"{" and b"error" in b[:60]

def dec(codec,data):
    c=(codec or "plain").lower()
    if c=="plain": return data
    if c=="reverse": return data[::-1]
    if c=="rot13": return codecs.decode(data,"rot_13")
    if c in ("base64","b64"): return base64.b64decode(data+"="*(-len(data)%4)).decode("utf-8","replace")
    if c in ("base64url","b64url"): return base64.urlsafe_b64decode(data+"="*(-len(data)%4)).decode("utf-8","replace")
    if c=="hex": return binascii.unhexlify(data).decode("utf-8","replace")
    if c=="gzip": return gzip.decompress(base64.b64decode(data+"="*(-len(data)%4))).decode("utf-8","replace")
    # fallback: try base64 then plain
    try: return base64.b64decode(data+"="*(-len(data)%4)).decode("utf-8","replace")
    except: return data

def puzzle_from_apk(b):
    try: z=zipfile.ZipFile(io.BytesIO(b))
    except: return None
    for n in z.namelist():
        if n.endswith("huntress_puzzle.json"):
            j=json.loads(z.read(n))
            return dec(j.get("codec"), j.get("data")).strip()
    return None

def main():
    cid=sys.argv[1]; dry="dry" in sys.argv[2:]
    st=start(cid); qs=st.get("questions") or []
    print("### %s mode=%s deadline=%s q=%d"%(cid,st.get("mode"),st.get("deadline"),len(qs)))
    nsets=len({q.get("set") for q in qs if q.get("set")}) or 1
    # fetch per-set APK: set K -> delivery K-1; single/time_trial -> default
    answers={}
    apk_cache={}
    def get_apk(setno):
        key=setno
        if key in apk_cache: return apk_cache[key]
        if setno:
            b=fetch(cid,d=setno-1)
            if is_err(b) or b[:2]!=b'PK': b=fetch(cid)
        else:
            b=fetch(cid)
        apk_cache[key]=b; return b
    for q in qs:
        setno=q.get("set")
        apk=get_apk(setno)
        ans=puzzle_from_apk(apk)
        print("  q=%s set=%s -> %s"%(q["id"],setno,ans))
        answers[q["id"]]=ans
    print("### submit:",json.dumps(answers))
    if dry: print("DRY"); return
    res=S.post(GM,data=json.dumps({"op":"submit","challenge":cid,"answers":answers})).json()
    print("### RESULT:",json.dumps({k:res.get(k) for k in ("result","flag","status","remaining","accepted","error")}))
main()
