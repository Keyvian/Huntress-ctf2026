import sys, re, json, io, zipfile, base64, codecs, gzip, requests
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
        if codec=="hex": return bytes.fromhex(data).decode("utf-8","replace").strip()
        if codec=="rot13": return codecs.decode(data,"rot13").strip()
        if codec in ("reverse","rev"): return data[::-1].strip()
        if codec in ("base64url","b64url"): return base64.urlsafe_b64decode(data+"==").decode("utf-8","replace").strip()
        if codec in ("gzip","gzip-base64"): return gzip.decompress(base64.b64decode(data)).decode("utf-8","replace").strip()
    except Exception as e: print("decode err",e)
    return data.strip()
def puzzle(blob):
    if blob[:2]!=b"PK": return None
    try: z=zipfile.ZipFile(io.BytesIO(blob))
    except: return None
    for n in z.namelist():
        b=z.read(n)
        if n.lower().endswith((".zip",".apk")) and b[:2]==b"PK":
            a=puzzle(b)
            if a: return a
        elif "huntress_puzzle.json" in n:
            j=json.loads(b.decode("utf-8","replace")); return decode(j.get("codec"),j.get("data",""))
    return None
def main():
    cid=sys.argv[1]; st=start(cid); qs=st.get("questions") or []
    print("mode",st.get("mode"),"deadline",st.get("deadline"),"qs",len(qs))
    answers={}
    for q in qs:
        qid=q["id"]; art=q.get("artifact") or ""
        m=re.search(r"delivery\s+(\d+)",art)
        if m: d=int(m.group(1))-1; blob=fetch(cid,d)   # artifact label is 1-based -> API 0-based
        else: blob=fetch(cid)
        ans=puzzle(blob)
        print("  %s art=%r -> %s" % (qid,art,ans))
        answers[qid]=ans
    print("submit",json.dumps(answers))
    if "dry" in sys.argv[2:]: return
    res=S.post(GM,data=json.dumps({"op":"submit","challenge":cid,"answers":answers})).json()
    print("RESULT",json.dumps({k:res.get(k) for k in ("result","flag","status","remaining","accepted","error")}))
main()
