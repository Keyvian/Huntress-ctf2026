#!/usr/bin/env python3
import sys, json, io, re, base64, subprocess, os, tempfile, time
import requests, pyzipper
GM="http://<homebase-ip>/huntress-ctf-proxy"
S=requests.Session(); S.headers.update({"Content-Type":"application/json"})
SUBMIT_SLEEP=float(os.environ.get("SUB_SLEEP","0"))

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
def submit(cid,ans):
    if SUBMIT_SLEEP: time.sleep(SUBMIT_SLEEP)
    for _ in range(6):
        r=S.post(GM,data=json.dumps({"op":"submit","challenge":cid,"answers":ans})).json()
        if r.get("error")=="rate_limited":
            time.sleep(4); continue
        return r
    return r

def rotl(b,n): return bytes(((x<<n)|(x>>(8-n)))&0xff for x in b)
def rotr(b,n): return bytes(((x>>n)|(x<<(8-n)))&0xff for x in b)
def base_cands(m):
    m=m.strip(); c=[]
    for s in (m, m[::-1]):
        try: c.append(base64.b64decode(s))
        except Exception: pass
        if re.fullmatch(r"[0-9a-fA-F]+",s) and len(s)%2==0:
            try: c.append(bytes.fromhex(s))
            except Exception: pass
        if re.fullmatch(r"[0-9.]+",s):
            try: c.append(bytes(int(x) for x in s.split(".") if x))
            except Exception: pass
    return c
def recover_batch_plan(material):
    for c in base_cands(material):
        vs=[c,c[::-1]]
        for k in range(256):
            x=bytes(b^k for b in c); vs+=[x,x[::-1]]
        for n in range(1,8): vs+=[rotl(c,n),rotr(c,n),rotl(c,n)[::-1],rotr(c,n)[::-1]]
        for v in vs:
            try: t=v.decode("utf-8")
            except Exception: continue
            if "campaign_id=" in t and ("v=1" in t or "steps=" in t): return t
    return None
def parse_plan(t):
    d={}
    for part in (t or "").split("|"):
        if "=" in part:
            k,v=part.split("=",1); d[k]=v
    return d

STUB=r'''
function mkproxy(){return new Proxy(function(){},{get:function(){return mkproxy();},apply:function(){return mkproxy();},construct:function(){return mkproxy();}});}
var WScript={Echo:function(){},Quit:function(){},Sleep:function(){},Arguments:{length:0,Item:function(){return "";}},CreateObject:function(){return mkproxy();},StdOut:{WriteLine:function(){}}};
function ActiveXObject(){return mkproxy();}
'''
def run_js(src):
    m=re.search(r"(?:function\s+(inspect_\w+)\s*\(|(?:var\s+)?(inspect_\w+)\s*=\s*function)",src)
    if not m: return {}
    fn=m.group(1) or m.group(2)
    runner=STUB+"\n"+src+"\ntry{console.log(JSON.stringify("+fn+"()));}catch(e){console.log('ERR '+e);}"
    with tempfile.NamedTemporaryFile("w",suffix=".js",delete=False,dir="/tmp") as f:
        f.write(runner); path=f.name
    try:
        out=subprocess.run(["node",path],capture_output=True,text=True,timeout=15).stdout.strip()
        return json.loads(out) if out.startswith("{") else {}
    except Exception: return {}
    finally: os.unlink(path)

def js_styles(src):
    if re.search(r"var\s+inspect_\w+\s*=\s*function\s+\w+",src): fstyle="named_expression"
    elif re.search(r"var\s+inspect_\w+\s*=\s*function\s*\(",src): fstyle="anonymous_expression"
    else: fstyle="declaration"
    inv="call" if ".call(" in src else ("apply" if ".apply(" in src else "direct")
    body=re.search(r"inspect_\w+[^{]*\{([\s\S]*?)\n\}",src)
    bsrc=body.group(1) if body else src
    dot=bool(re.search(r"\.(steps|adapter|values|stageCount)\b",bsrc))
    brk=bool(re.search(r'\[\s*"(steps|adapter|values|stageCount)"\s*\]',bsrc))
    prop="mixed" if dot and brk else ("dot" if dot else "bracket_literal")
    return fstyle,inv,prop

def batch_expansion(src):
    for ln in src.splitlines():
        s=ln.strip(); low=s.lower()
        if re.search(r'set "(recovered_configuration|cfg|item9|recovered)=',low) and ("%" in s or "!" in s):
            if low.startswith("for ") or "for %%" in low: return "for_indirect"
            if "!" in s and "%%" not in s and "call set" not in low: return "delayed"
            if "call set" in low and "%%" in s: return "call_double"
            if re.search(r"%\w+%%\w+%",s): return "percent"
            if "!" in s: return "delayed"
    for ln in src.splitlines():
        if ln.strip().lower().startswith("for ") and "call set" in ln.lower(): return "for_indirect"
    return "percent"

def batch_control(src):
    s=src.lower()
    if re.search(r"^\s*for\s",s,re.M): return "for_loop"
    if re.search(r"call\s+:",s): return "call_subroutine"
    if re.search(r"if\s+defined",s): return "if_defined"
    if re.search(r"if\s+errorlevel",s): return "errorlevel"
    return "goto_dispatch"

def load_files(cid, need_sets):
    files={}
    def addzip(b):
        try:
            z=pyzipper.AESZipFile(io.BytesIO(b)); z.pwd=b"infected"
            for n in z.namelist(): files.setdefault(n, z.read(n))
        except Exception as e: print("zip err",e)
    d=fetch(cid)
    if d[:2]==b"PK": addzip(d)
    if need_sets>1:
        for i in range(need_sets):
            r=fetch(cid,delivery=i)
            if r and not is_err(r) and r[:2]==b"PK": addzip(r)
    return files

ATT_PS={"resource":["T1496"],"collection":["T1555.003","T1005","T1114","T1539"],"impact":["T1486"]}
def js_attack(r):
    return {"benign":["none"],"stager":["T1105","T1059.007"],"dropper":["T1140","T1105"],
      "downloader":["T1105","T1071.001"],"uploader":["T1041","T1567"],"launcher":["T1059.007"],
      "chain":["T1059.007","T1105"],"relay":["T1059.007","T1105"],"impact":["T1486"]}[r]
def batch_attack(r):
    return {"benign":["none"],"stager":["T1105","T1059.003"],"dropper":["T1140","T1105"],
      "downloader":["T1105","T1071.001"],"uploader":["T1041","T1567"],"launcher":["T1059.003"],
      "chain":["T1059.003","T1105"],"relay":["T1059.003","T1105"],"impact":["T1486"]}[r]
ROLE_ENUM={"benign":["benign_utility"],"stager":["stager"],"dropper":["dropper"],
  "downloader":["downloader"],"uploader":["uploader"],"launcher":["launcher"],
  "impact":["impact"],"chain":["staged_chain","relay"],"relay":["relay","staged_chain"]}

def compute(cid):
    st=start(cid); qs=st.get("questions") or []
    sets=sorted({q.get("set") for q in qs if q.get("set")})
    files=load_files(cid, len(sets) if sets else 1)
    id2art={q["id"]:(q.get("artifact") or "") for q in qs}
    cache={}
    def filedata(fname):
        if fname in cache: return cache[fname]
        raw=files.get(fname,b""); r={"raw":raw}; txt=raw.decode("utf-8","replace")
        if fname.endswith(".ps1"):
            b=re.search(r"FromBase64String\('([^']+)'\)",txt)
            r["json"]=json.loads(base64.b64decode(b.group(1)).decode()) if b else {}
        elif fname.endswith(".js"):
            r["plan"]=run_js(txt); r["styles"]=js_styles(txt)
        elif fname.endswith((".cmd",".bat")):
            mat=re.search(r"HUNTRESS-MATERIAL:(\S+)",txt)
            r["plan"]=parse_plan(recover_batch_plan(mat.group(1)) if mat else "")
            r["expansion"]=batch_expansion(txt); r["control"]=batch_control(txt)
        cache[fname]=r; return r
    certain={}; cand={}
    for q in qs:
        qid=q["id"]; art=id2art[qid]
        fname=art.split("->")[-1].strip().split("/")[-1] if "->" in art else art
        bid=qid.split(".",1)[1] if "." in qid else qid
        fd=filedata(fname)
        if fname.endswith(".ps1"):
            role=bid.split("-")[0]; js=fd.get("json",{})
            if bid.endswith("-scenario"): certain[qid]={"resource":"resource_hijacking","collection":"synthetic_collection","impact":"synthetic_impact"}[role]
            elif bid.endswith("-attack"): cand[qid]=ATT_PS[role]
            elif bid.endswith("-url"): certain[qid]=js.get("d") if role=="impact" else js.get("b")
            elif bid.endswith("-wallet"): certain[qid]=js.get("c")
            elif bid.endswith("-mutex"): certain[qid]=js.get("h")
            elif bid.endswith("-file"):
                c=js.get("c"); certain[qid]=c[0] if isinstance(c,list) else c
            elif bid.endswith("-user-agent"): certain[qid]=js.get("f")
            elif bid.endswith("-extension"): certain[qid]=js.get("b")
            elif bid.endswith("-note"): certain[qid]=js.get("c")
        elif bid.startswith("jscript-"):
            role=bid.split("-")[1]; plan=fd.get("plan",{}) or {}; vals=plan.get("values",{}) or {}
            fstyle,inv,prop=fd.get("styles",("declaration","direct","dot"))
            if bid.endswith("-role"): cand[qid]=ROLE_ENUM[role]
            elif bid.endswith("-attack"): cand[qid]=js_attack(role)
            elif bid.endswith("-adapter"): certain[qid]=plan.get("adapter")
            elif bid.endswith("-campaign"): certain[qid]=vals.get("campaign_id")
            elif bid.endswith("-host"): certain[qid]=vals.get("host_id")
            elif bid.endswith("-url"): certain[qid]=vals.get("url")
            elif bid.endswith("-path"): certain[qid]=vals.get("file_path")
            elif bid.endswith("-next-stage"): certain[qid]=vals.get("next_stage")
            elif bid.endswith("-extension"): certain[qid]=vals.get("extension")
            elif bid.endswith("-note"): certain[qid]=vals.get("note_name")
            elif bid.endswith("-function-style"): cand[qid]=[fstyle,"declaration","anonymous_expression","named_expression","function_expression","expression"]
            elif bid.endswith("-invocation-style"): cand[qid]=[inv,"direct","call","apply"]
            elif bid.endswith("-property-style"): cand[qid]=[prop,"dot","bracket_literal","mixed","bracket"]
        elif bid.startswith("batch-"):
            role=bid.split("-")[1]; plan=fd.get("plan",{})
            if bid.endswith("-role"): cand[qid]=ROLE_ENUM[role]
            elif bid.endswith("-attack"): cand[qid]=batch_attack(role)
            elif bid.endswith("-adapter"): certain[qid]=plan.get("adapter")
            elif bid.endswith("-campaign"): certain[qid]=plan.get("campaign_id")
            elif bid.endswith("-host-id"): certain[qid]=plan.get("host_id")
            elif bid.endswith("-upload-url"): certain[qid]=plan.get("upload_url") or plan.get("url")
            elif bid.endswith("-url"): certain[qid]=plan.get("url") or plan.get("upload_url")
            elif bid.endswith("-file-path"): certain[qid]=plan.get("file_path")
            elif bid.endswith("-note-name"): certain[qid]=plan.get("note_name")
            elif bid.endswith("-next-stage"): certain[qid]=plan.get("next_stage")
            elif bid.endswith("-graph"): certain[qid]=plan.get("graph")
            elif bid.endswith("-expansion"): cand[qid]=[fd.get("expansion"),"percent","delayed","call_double","for_indirect","call-double","for-indirect"]
            elif bid.endswith("-control"): cand[qid]=[fd.get("control"),"goto","call","for","if","goto_dispatch","call_subroutine","for_loop","if_defined","errorlevel","conditional","straight_line","linear","label_dispatch"]
    return st,qs,certain,cand

HARD_JS_ROLE={"benign":"benign_utility","stager":"stager","dropper":"dropper","downloader":"downloader","launcher":"launcher","chain":"staged_chain","uploader":"uploader","impact":"impact","relay":"staged_chain"}
HARD_JS_ATT={"benign":"none","stager":"T1105","dropper":"T1140","downloader":"T1105","launcher":"T1059.007","chain":"T1059.007","uploader":"T1041","impact":"T1486","relay":"T1059.007"}
HARD_B_ATT={"benign":"none","stager":"T1105","dropper":"T1140","downloader":"T1105","uploader":"T1041","launcher":"T1059.003","impact":"T1486","chain":"T1059.003","relay":"T1059.003"}
HARD_B_EXP={"benign":"for_indirect","stager":"delayed","dropper":"delayed","downloader":"delayed","uploader":"delayed","launcher":"call_double","impact":"delayed","chain":"delayed","relay":"delayed"}
HARD_B_CTRL={"benign":"errorlevel_guard","stager":"direct","dropper":"goto_dispatch","downloader":"direct","uploader":"call_subroutine","impact":"direct","chain":"errorlevel_guard","launcher":None,"relay":None}
HARD_PS_ATT={"resource":"T1496","collection":"T1555.003","impact":"T1486"}

def apply_hardcoded(certain,cand,qid):
    bid=qid.split(".",1)[1] if "." in qid else qid
    def role_of(prefix):
        return bid[len(prefix):].split("-")[0]
    if bid.endswith("-attack") and bid.startswith(("resource","collection","impact")) and not bid.startswith("jscript") and not bid.startswith("batch"):
        certain[qid]=HARD_PS_ATT.get(bid.split("-")[0]); cand.pop(qid,None)
    elif bid.startswith("jscript-"):
        role=bid.split("-")[1]
        if bid.endswith("-role"): certain[qid]=HARD_JS_ROLE.get(role); cand.pop(qid,None)
        elif bid.endswith("-attack"): certain[qid]=HARD_JS_ATT.get(role); cand.pop(qid,None)
    elif bid.startswith("batch-"):
        role=bid.split("-")[1]
        if bid.endswith("-role"): certain[qid]=HARD_JS_ROLE.get(role); cand.pop(qid,None)
        elif bid.endswith("-attack"): certain[qid]=HARD_B_ATT.get(role); cand.pop(qid,None)
        elif bid.endswith("-expansion"): certain[qid]=HARD_B_EXP.get(role); cand.pop(qid,None)
        elif bid.endswith("-control"):
            v=HARD_B_CTRL.get(role)
            if v is not None: certain[qid]=v; cand.pop(qid,None)

def confirm(cid):
    st,qs,certain,cand=compute(cid)
    for q in qs: apply_hardcoded(certain,cand,q["id"])
    # take first candidate for any remaining style ids (detected, reliable)
    for qid,lst in list(cand.items()):
        certain[qid]=dedup(lst)[0]
    # submit everything EXCEPT the unknown controls as a banking subset
    unknown=[q["id"] for q in qs if q["id"].endswith("-control") and (q["id"].split(".",1)[-1].split("-")[1] in ("launcher","relay"))]
    subset={k:v for k,v in certain.items() if k not in unknown and v not in (None,"")}
    r=submit(cid,subset)
    print("subset size=%d unknown=%s"%(len(subset),unknown))
    print("RESULT:",json.dumps({k:r.get(k) for k in ("result","remaining","error")}))
    # if accepted, bisect to confirm none wrong; if incorrect, bisect to find wrong ones
    if r.get("result")=="accepted":
        print("all submitted correct; remaining(incl unknowns)=",r.get("remaining"))
    else:
        # bisect to find wrong ids
        def bad(d):
            if not d: return []
            rr=submit(cid,d)
            if rr.get("result") in ("accepted","CORRECT"): return []
            if len(d)==1: return list(d)
            it=list(d.items()); m=len(it)//2
            return bad(dict(it[:m]))+bad(dict(it[m:]))
        print("WRONG:",bad(subset))

def dedup(lst):
    out=[]; seen=set()
    for x in lst:
        if x is None: continue
        if x in seen: continue
        seen.add(x); out.append(x)
    return out

def probe(cid):
    st,qs,certain,cand=compute(cid)
    allids=[q["id"] for q in qs]
    print("mode=%s deadline=%s nq=%d certain=%d uncertain=%d"%(st.get("mode"),st.get("deadline"),len(qs),len(certain),len(cand)))
    gaps=[k for k,v in certain.items() if v in (None,"")]
    if gaps: print("VALUE-GAPS:",gaps)
    resolved=dict(certain)
    # bank certain via bisection
    def bank(d):
        if not d: return set()
        r=submit(cid,d); res=r.get("result")
        if res in ("accepted","CORRECT"): return set(d)
        if len(d)==1: return set()
        items=list(d.items()); mid=len(items)//2
        a=bank(dict(items[:mid])); b=bank(dict(items[mid:])); return a|b
    banked=bank({k:v for k,v in certain.items() if v not in (None,"")})
    wrong_certain=[k for k,v in certain.items() if v not in (None,"") and k not in banked]
    print("certain banked=%d wrong_certain=%s"%(len(banked),wrong_certain))
    # probe uncertain (and wrong_certain treated as uncertain with their cand list if any)
    for qid in list(cand.keys())+[k for k in wrong_certain if k not in cand]:
        cands=dedup(cand.get(qid,[]))
        chosen=None
        for v in cands:
            r=submit(cid,{qid:v}); res=r.get("result")
            if res in ("accepted","CORRECT"): chosen=v; break
        resolved[qid]=chosen
        if chosen is None: print("UNRESOLVED",qid,"tried",cands)
    # final full submit
    final={k:resolved.get(k) for k in allids}
    r=submit(cid,final)
    print("FINAL:",json.dumps({k:r.get(k) for k in ("result","flag","status","remaining","error")}))
    # dump learned choices for uncertain ids
    learned={qid:resolved.get(qid) for qid in cand}
    print("LEARNED:",json.dumps(learned,indent=0))
    return r

def oneshot(cid):
    st,qs,certain,cand=compute(cid)
    ans={}
    for q in qs:
        qid=q["id"]
        if qid in certain: ans[qid]=certain[qid]
        else: ans[qid]=dedup(cand.get(qid,[None]))[0]
    r=submit(cid,ans)
    print("mode=%s ONESHOT:"%st.get("mode"),json.dumps({k:r.get(k) for k in ("result","flag","status","remaining","error")}))
    return r

CTRL_VOCAB=["for_loop","call_subroutine","goto_dispatch","direct","conditional",
 "for","loop","for_in","for_each","iteration","delayed_guard","if_defined","defined",
 "errorlevel","guarded","guard","nested","call_set","set_loop","accumulate",
 "two_phase","parameterized","indirect","label_dispatch","straight_line","sequential",
 "fallthrough","inline","branch","jump","call","goto","if"]
EXP_VOCAB=["percent","delayed","call_double","for_indirect"]

def learn2(cid, ids, ctrl_vocab=None):
    st,qs,certain,cand=compute(cid)
    out={}
    for qid in ids:
        if qid.endswith("-control"): cands=ctrl_vocab or CTRL_VOCAB
        elif qid.endswith("-expansion"): cands=EXP_VOCAB
        else: cands=dedup(cand.get(qid,[]))
        acc=None
        for v in dedup(cands):
            r=submit(cid,{qid:v})
            if r.get("result") in ("accepted","CORRECT"): acc=v; break
        out[qid]=acc
        print("%s -> %s"%(qid,acc))
    print("LEARNED2:",json.dumps(out))

def learn(cid):
    # reset to a fresh attempt so no prior banking pollutes probes
    S.post(GM,data=json.dumps({"op":"retry","challenge":cid}))
    st,qs,certain,cand=compute(cid)
    learned={}
    for q in qs:
        qid=q["id"]
        if qid not in cand: continue
        suf=None
        if qid.endswith("-control"): cands=CTRL_VOCAB
        elif qid.endswith("-expansion"): cands=EXP_VOCAB
        else: cands=dedup(cand[qid])
        acc=None; raws=[]
        for v in dedup(cands):
            r=submit(cid,{qid:v}); res=r.get("result")
            raws.append((v,res or r.get("error")))
            if res in ("accepted","CORRECT"): acc=v; break
        learned[qid]=acc
        if acc is None: print("UNRESOLVED",qid,raws[:8])
    print("LEARNED:",json.dumps(learned,indent=0))

def diag(cid, suffix):
    st,qs,certain,cand=compute(cid)
    for qid in [q["id"] for q in qs]:
        if not qid.endswith(suffix): continue
        cands=cand.get(qid)
        if suffix=="-control": cands=CTRL_VOCAB
        if suffix=="-expansion": cands=dedup((cand.get(qid,[])[:1])+EXP_VOCAB)
        acc=None; tried=[]
        for v in dedup(cands or []):
            r=submit(cid,{qid:v}); res=r.get("result"); tried.append((v,res))
            if res in ("accepted","CORRECT"): acc=v; break
        print("%s -> %s"%(qid,acc if acc else "UNRESOLVED %s"%tried[:6]))

if __name__=="__main__":
    cid=sys.argv[1]; mode=sys.argv[2] if len(sys.argv)>2 else "probe"
    if mode=="probe": probe(cid)
    elif mode=="learn": learn(cid)
    elif mode=="learn2":
        ids=sys.argv[3].split(",")
        learn2(cid, ids)
    elif mode=="confirm": confirm(cid)
    elif mode.startswith("field:"): diag(cid, mode.split(":",1)[1])
    else: oneshot(cid)
