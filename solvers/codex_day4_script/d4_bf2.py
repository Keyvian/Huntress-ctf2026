import sys, re, json, time, pathlib
sys.path.insert(0,'/home/HuntressCTF/codex_day3')
import requests
sys.argv=['x']
exec(open('/home/HuntressCTF/codex_day4_script/solve_d4.py').read().split('if __name__')[0])
S=requests.Session(); S.headers.update({'Content-Type':'application/json'})
ROLES=['benign','stager','dropper','downloader','uploader','launcher','impact','chain','relay']
CTRL=['direct','select_case','if_guard','opaque_predicate','while_loop','for_loop','do_loop','do_while',
 'nested_if','if_else','case_dispatch','select_dispatch','conditional_guard','guarded','loop_guard',
 'while_guard','straight_line','sequential','inline','branch','looped','redim_loop','goto_dispatch',
 'call_subroutine','sub_dispatch','conditional','nested_guard','dispatch']
ATK={'benign':['none'],'stager':['T1105','T1059.005'],'dropper':['T1140','T1027','T1059.005'],
 'downloader':['T1105','T1059.005'],'uploader':['T1041','T1059.005'],'launcher':['T1059.005','T1059.003'],
 'impact':['T1486'],'chain':['T1059.005','T1105'],'relay':['T1059.005','T1105']}
EXP=['for_indirect','call_double','delayed','percent']
BCTRL=['direct','goto_dispatch','call_subroutine','errorlevel_guard','if_guard']
def submit(ans):
    for _ in range(6):
        r=S.post(U,data=json.dumps({'op':'submit','challenge':C,'answers':ans})).json()
        if r.get('error')=='rate_limited': time.sleep(1.4); continue
        return r
    return r
st=S.post(U,data=json.dumps({'op':'start','challenge':C})).json(); ids=st['answer_ids']
files=gather(S.get(U,params={'op':'artifact','challenge':C}).content)
a,_=SE.analyze({k:v for k,v in files.items() if not k.endswith('.vbs')}); a.update(analyze_vbs(files))
a={k:a[k] for k in ids if k in a}
unc={}
for r in ROLES:
    for f,c in ((f'vbscript-{r}-control',CTRL),(f'vbscript-{r}-attack',ATK[r]),
                (f'batch-{r}-expansion',EXP),(f'batch-{r}-control',BCTRL)):
        if f in a: unc[f]=[a[f]]+[x for x in c if x!=a[f]]
base={k:v for k,v in a.items() if k not in unc}
r0=submit(base); print('base',{k:r0.get(k) for k in ('result','remaining')})
flag=None; unresolved=[]
for f in list(unc):
    hit=None
    for cand in unc[f]:
        r=submit({**base,f:cand}); res=r.get('result')
        if res=='CORRECT': flag=r.get('flag'); base[f]=cand; break
        if res=='accepted': base[f]=cand; hit=cand; break
    if flag: print('CORRECT',flag); break
    if hit is None: unresolved.append(f)   # DON'T poison base
print('unresolved:',unresolved)
if not flag:
    rf=submit(base); print('final',{k:rf.get(k) for k in ('result','remaining','flag')}); flag=rf.get('flag')
print('VBS control:',{r:base.get(f'vbscript-{r}-control') for r in ROLES})
print('VBS attack:',{r:base.get(f'vbscript-{r}-attack') for r in ROLES})
pathlib.Path('/home/HuntressCTF/codex_day4_script/d4_base.json').write_text(json.dumps(base))
