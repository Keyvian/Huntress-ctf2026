import sys, re, json, io, zipfile, base64, codecs, gzip
import requests
GM="http://<homebase-ip>/huntress-ctf-proxy"
S=requests.Session(); S.headers.update({"Content-Type":"application/json"})

def start(c):
    r=S.post(GM,data=json.dumps({"op":"start","challenge":c})).json()
    if r.get("answer_ids") is None or r.get("error"):
        r2=S.post(GM,data=json.dumps({"op":"retry","challenge":c})).json()
        if r2.get("answer_ids"): r=r2
    return r
def fetch(c,d=None):
    p={"op":"artifact","challenge":c}
    if d is not None: p["delivery"]=d
    return S.get(GM,params=p).content
def decode(codec,data):
    codec=(codec or "plain").lower()
    try:
        if codec=="plain": return data.strip()
        if codec in ("base64","b64"): return base64.b64decode(data).decode("utf-8","replace").strip()
        if codec in ("base64url","b64url"): return base64.urlsafe_b64decode(data+"==").decode("utf-8","replace").strip()
        if codec=="hex": return bytes.fromhex(data).decode("utf-8","replace").strip()
        if codec=="rot13": return codecs.decode(data,"rot13").strip()
        if codec in ("reverse","rev"): return data[::-1].strip()
        if codec in ("gzip","gz","gzip-base64","gzip_base64"): return gzip.decompress(base64.b64decode(data)).decode("utf-8","replace").strip()
    except Exception as e: print("decode err",codec,e)
    return data.strip()
def apk_info(blob):
    if blob[:2]!=b"PK": return None,set()
    try: z=zipfile.ZipFile(io.BytesIO(blob))
    except: return None,set()
    ans=None; cases=set()
    for n in z.namelist():
        b=z.read(n)
        if n.lower().endswith((".zip",".apk")) and b[:2]==b"PK":
            a2,c2=apk_info(b); ans=ans or a2; cases|=c2
        elif "huntress_puzzle.json" in n:
            try:
                j=json.loads(b.decode("utf-8","replace")); ans=decode(j.get("codec"),j.get("data",""))
            except Exception as e: print("puzzle err",e)
        elif n.endswith(".dex"):
            cases|=set(re.findall(r"MOB-\d+-[0-9A-Fa-f]+", b.decode("latin1")))
    return ans,cases
def main():
    cid=sys.argv[1]; st=start(cid)
    qs=st.get("questions") or []
    print("mode",st.get("mode"),"deadline",st.get("deadline"),"qs",len(qs))
    # build case -> answer map across default + all valid deliveries
    case2ans={}
    blobs=[fetch(cid)]
    for d in range(0,8):
        b=fetch(cid,d)
        if b[:1]==b"{": break
        blobs.append(b)
    for b in blobs:
        ans,cases=apk_info(b)
        for c in cases:
            if ans: case2ans[c.upper()]=ans
    answers={}
    for q in qs:
        qid=q["id"]; ask=q.get("question") or ""
        mc=re.search(r"MOB-\d+-[0-9A-F]+",ask,re.I)
        case=mc.group(0).upper() if mc else None
        ans=case2ans.get(case)
        print("  %s case=%s -> %s" % (qid,case,ans))
        answers[qid]=ans
    print("submit",json.dumps(answers))
    if "dry" in sys.argv[2:]: return
    res=S.post(GM,data=json.dumps({"op":"submit","challenge":cid,"answers":answers})).json()
    print("RESULT",json.dumps({k:res.get(k) for k in ("result","flag","status","remaining","accepted","error")}))
main()
