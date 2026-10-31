import sys, re, json, time, pathlib
sys.path.insert(0,'/home/HuntressCTF/codex_day3')
import requests
sys.argv=['x']
exec(open('/home/HuntressCTF/codex_day4_script/solve_d4.py').read().split('if __name__')[0])
S=requests.Session(); S.headers.update({'Content-Type':'application/json'})

ROLES=['benign','stager','dropper','downloader','uploader','launcher','impact','chain','relay']
CTRL_VBS=['direct','if_guard','select_case','opaque_predicate','while_loop','select_dispatch','conditional_guard','nested_guard','for_loop','goto_dispatch','call_subroutine','loop_guard','dispatch','guarded']
ATK={'benign':['none'],'stager':['T1105','T1059.005'],'dropper':['T1140','T1059.005','T1027'],
 'downloader':['T1105','T1059.005'],'uploader':['T1041','T1059.005'],'launcher':['T1059.005','T1059.003'],
 'impact':['T1486'],'chain':['T1059.005','T1105','T1059.007'],'relay':['T1059.005','T1105','T1059.007']}
EXP=['for_indirect','call_double','delayed','percent']
BCTRL=['direct','goto_dispatch','call_subroutine','errorlevel_guard','if_guard']

def submit(ans):
    for _ in range(6):
        r=S.post(U,data=json.dumps({'op':'submit','challenge':C,'answers':ans})).json()
        if r.get('error')=='rate_limited': time.sleep(1.4); continue
        return r
    return r

st=S.post(U,data=json.dumps({'op':'start','challenge':C})).json()
ids=st['answer_ids']
files=gather(S.get(U,params={'op':'artifact','challenge':C}).content)
a,_=SE.analyze({k:v for k,v in files.items() if not k.endswith('.vbs')})
a.update(analyze_vbs(files)); a={k:a[k] for k in ids if k in a}

# uncertain fields -> ordered candidates
unc={}
for r in ROLES:
    for f,c in ((f'vbscript-{r}-control',CTRL_VBS),(f'vbscript-{r}-attack',ATK[r])):
        if f in a: unc[f]=[a[f]]+[x for x in c if x!=a[f]]
    for f,c in ((f'batch-{r}-expansion',EXP),(f'batch-{r}-control',BCTRL)):
        if f in a: unc[f]=[a[f]]+[x for x in c if x!=a[f]]

base={k:v for k,v in a.items() if k not in unc}
r0=submit(base)
print('base',{k:r0.get(k) for k in ('result','remaining','error')},'held',len(unc))
if r0.get('result')!='accepted':
    print('BASE NOT ACCEPTED — a confident field is wrong'); sys.exit()
flag=None
for f in list(unc):
    got=False
    for cand in unc[f]:
        r=submit({**base,f:cand})
        if r.get('result')=='CORRECT': flag=r.get('flag'); print('CORRECT',flag); got=True; break
        if r.get('result')=='accepted': base[f]=cand; got=True; break
    if not got: print('UNRESOLVED',f,'tried',unc[f]); base[f]=unc[f][0]
    if flag: break
if not flag:
    rf=submit(base); flag=rf.get('flag'); print('final',{k:rf.get(k) for k in ('result','remaining','flag')})
# show learned control/attack maps
print('VBS control:',{r:base.get(f'vbscript-{r}-control') for r in ROLES})
print('VBS attack:',{r:base.get(f'vbscript-{r}-attack') for r in ROLES})
pathlib.Path('/home/HuntressCTF/codex_day4_script/d4_base.json').write_text(json.dumps(base))
