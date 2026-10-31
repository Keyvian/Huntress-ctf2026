import sys, re, json, time, pathlib, io, pyzipper
sys.path.insert(0, '/home/HuntressCTF/codex_day3')
import solve_expansion as SE
exec(open('/home/HuntressCTF/codex_day3/exp_driver.py').read().split('SE.batch_decode = batch_decode_fixed')[0])
SE.batch_decode = batch_decode_fixed
from solve_table import gather, U
import requests
S = requests.Session(); S.headers.update({'Content-Type': 'application/json'})
C = 'script-analysis-day-04-shell-contrast'
NAMES = {'host-context':'benign','memory-stage':'stager','embedded-write':'dropper','remote-write':'downloader','outbound-transfer':'uploader','local-dispatch':'launcher','impact-plan':'impact','staged-handoff':'chain','relay-handoff':'relay'}

def parse_ints(rep, mat):
    if rep.startswith('hex'):
        if ':' in mat: return [int(x,16) for x in mat.split(':') if x]
        return list(bytes.fromhex(mat))
    return [int(x) for x in re.split(r'[|,\-\s]+', mat.strip()) if x]

def vbs_plan(s):
    mat = re.search(r'Material_\w+\s*=\s*"([^"]*)"', s).group(1)
    codec = re.search(r'Codec_\w+\s*=\s*"([^"]*)"', s).group(1)
    rep, xf, param = (codec.split('|') + ['','',''])[:3]
    nums = parse_ints(rep, mat); keys = [int(x,16) for x in param.split(',')] if param else []
    def good(bs):
        try: t = bytes(b%256 for b in bs).decode('latin1')
        except: return None
        return t if t.startswith('v=1|') else None
    cands = []
    for arr in (nums, nums[::-1]):
        if xf=='subtract_modulo_256':
            for k in (keys or [0]): cands += [[(n+k)%256 for n in arr],[(n-k)%256 for n in arr]]
        elif xf=='single_byte_xor':
            for k in (keys or [0]): cands.append([n^k for n in arr])
        elif xf=='repeating_key_xor':
            if keys: cands.append([n^keys[i%len(keys)] for i,n in enumerate(arr)])
        elif xf=='rolling_xor':
            k0=keys[0] if keys else 0
            cands += [[n^((k0+i)%256) for i,n in enumerate(arr)],[n^((k0-i)%256) for i,n in enumerate(arr)]]
            r=[];k=k0
            for n in arr: v=n^k; r.append(v); k=v
            cands.append(r)
            r=[];k=k0
            for n in arr: v=n^k; r.append(v); k=n
            cands.append(r)
        else: cands.append(arr)
    plan=None
    for c in cands:
        g=good(c)
        if g: plan=g; break
    d={}
    if plan:
        for part in plan.split('|'):
            if '=' in part: k,v=part.split('=',1); d[k]=v
    return d, rep, xf

VBS_IND = {'benign':('host-id','host_id'),'stager':('url','url'),'dropper':('file-path','file_path'),
 'downloader':('url','url'),'uploader':('upload-url','upload_url'),'launcher':('file-path','file_path'),
 'impact':('extension','extension'),'chain':('next-stage','next_stage'),'relay':('next-stage','next_stage')}
VBS_ATTACK = {'benign':'none','stager':'T1059.005','dropper':'T1140','downloader':'T1059.005',
 'uploader':'T1059.005','launcher':'T1059.005','impact':'T1486','chain':'T1059.005','relay':'T1059.005'}

def analyze_vbs(files):
    out={}
    for n,b in files.items():
        base=pathlib.PurePosixPath(n).name
        if not base.endswith('.vbs'): continue
        role=NAMES.get(base[:-4])
        if not role: continue
        s=b.decode('utf-8-sig','replace')
        d,rep,xf=vbs_plan(s)
        p='vbscript-'+role+'-'
        out[p+'role']='benign_utility' if role=='benign' else 'staged_chain' if role in ('chain','relay') else role
        out[p+'attack']=VBS_ATTACK[role]
        out[p+'adapter']=d.get('adapter','')
        out[p+'campaign']=d.get('campaign_id','')
        out[p+'representation']=rep
        out[p+'transform']=xf
        suf,key=VBS_IND[role]
        if key in d: out[p+suf]=d[key]
        out[p+'control']='direct'  # placeholder; brute-forced
    return out

def submit(ans):
    for _ in range(5):
        r=S.post(U,data=json.dumps({'op':'submit','challenge':C,'answers':ans})).json()
        if r.get('error')=='rate_limited': time.sleep(1.4); continue
        return r
    return r

if __name__=='__main__':
    st=S.post(U,data=json.dumps({'op':'start','challenge':C})).json()
    ids=st['answer_ids']
    files=gather(S.get(U,params={'op':'artifact','challenge':C}).content)
    nonvbs={k:v for k,v in files.items() if not k.endswith('.vbs')}
    a,_=SE.analyze(nonvbs)
    a.update(analyze_vbs(files))
    a={k:a[k] for k in ids if k in a}
    print('computed',len(a),'of',len(ids),'missing:',[k for k in ids if k not in a][:20])
    r=submit(a)
    print('FULL submit:',{k:r.get(k) for k in ('result','remaining','flag','error')})
    (pathlib.Path.home()/'codex_day4_script'/'d4_answers.json').write_text(json.dumps(a))
