import requests, json, zipfile, io
GM="http://<homebase-ip>/huntress-ctf-proxy"
S=requests.Session(); S.headers.update({"Content-Type":"application/json"})
C="mobile-android-day-04-pending-intent-relay"
st=S.post(GM,data=json.dumps({"op":"start","challenge":C})).json()
print("mode",st.get("mode"),"deadline",st.get("deadline"),"answer_ids",st.get("answer_ids"))
for q in st.get("questions",[]):
    print("Q id=%r artifact=%r ask=%r fmt=%r"%(q.get("id"),q.get("artifact"),q.get("question"),q.get("answer_format")))
raw=S.get(GM,params={"op":"artifact","challenge":C}).content
print("artifact bytes",len(raw),"isPK",raw[:2]==b"PK")
if raw[:2]==b"PK":
    z=zipfile.ZipFile(io.BytesIO(raw))
    names=z.namelist()
    print("members:",len(names))
    for n in names:
        if "puzzle" in n.lower() or n.startswith("assets/"):
            print("  ",n)
    for n in names:
        if n.lower().endswith("huntress_puzzle.json"):
            print("=== %s ==="%n); print(z.read(n).decode("utf-8","replace")[:600])
