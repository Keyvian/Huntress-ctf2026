import sys, re, json, io, zipfile, base64, binascii, codecs, gzip, time
import requests
GM="http://<homebase-ip>/huntress-ctf-proxy"
S=requests.Session(); S.headers.update({"Content-Type":"application/json"})
BASE="mobile-android-day-04-pending-intent-relay"

def decode(p):
    c=(p.get("codec") or "").lower(); d=p.get("data",""); k=p.get("key")
    try:
        if c=="plain": return d
        if c=="reverse": return d[::-1]
        if c in ("base64","b64","base64url"):
            s=d.replace("-","+").replace("_","/"); s+="="*(-len(s)%4)
            return base64.b64decode(s).decode("utf-8","replace")
        if c=="hex": return binascii.unhexlify(re.sub(r"\s","",d)).decode("utf-8","replace")
        if c=="rot13": return codecs.decode(d,"rot_13")
        if c=="gzip": return gzip.decompress(base64.b64decode(d)).decode("utf-8","replace")
        if c=="xor":
            raw=base64.b64decode(d+"="*(-len(d)%4))
            return bytes(b^int(k) for b in raw).decode("utf-8","replace")
    except Exception as e:
        return "DECODE_ERR:%s"%e
    return "UNKNOWN_CODEC:%s"%c

def puzzle_from(raw):
    if raw[:2]!=b"PK": return None
    z=zipfile.ZipFile(io.BytesIO(raw))
    for n in z.namelist():
        if n.lower().endswith("huntress_puzzle.json"):
            return json.loads(z.read(n))
    return None

def fetch(C,delivery=None):
    p={"op":"artifact","challenge":C}
    if delivery is not None: p["delivery"]=delivery
    return S.get(GM,params=p).content

def submit(C,ans):
    for _ in range(4):
        r=S.post(GM,data=json.dumps({"op":"submit","challenge":C,"answers":ans})).json()
        if r.get("error")=="rate_limited": time.sleep(1.6); continue
        return r
    return r

def solve(mode):
    C=BASE+("/"+mode if mode!="single_solve" else "")
    for whole in range(6):
        st=S.post(GM,data=json.dumps({"op":"start" if whole==0 else "retry","challenge":C})).json()
        if "answer_ids" not in st:
            st=S.post(GM,data=json.dumps({"op":"start","challenge":C})).json()
        if "answer_ids" not in st:
            print(mode,"start err",{k:st.get(k) for k in ("error","result")}); time.sleep(1.2); continue
        ids=st["answer_ids"]
        sets=sorted({int(m[1]) for x in ids if (m:=re.match(r"set(\d+)\.",x))})
        ans={}
        if sets:
            for sn in sets:
                raw=fetch(C,sn-1)
                if raw[:2]!=b"PK": raw=fetch(C)
                p=puzzle_from(raw); ans["set%d.answer"%sn]=decode(p) if p else None
        else:
            ans["answer"]=decode(puzzle_from(fetch(C)))
        ans={k:ans[k] for k in ids if k in ans}
        r=submit(C,ans)
        print(mode,"whole",whole,"submit",{k:r.get(k) for k in ("result","remaining","flag","error")},"ans_sample",list(ans.values())[0])
        if r.get("result")=="CORRECT": return r.get("flag")
        time.sleep(1.2)
    return None

if __name__=="__main__":
    for m in ["single_solve","time_trial","mastery"]:
        f=solve(m); print("==>",m,"FLAG",f,flush=True)
