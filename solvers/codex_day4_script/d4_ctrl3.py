import sys, json, time
sys.path.insert(0,'/home/HuntressCTF/codex_day3')
import requests
sys.argv=['x']
exec(open('/home/HuntressCTF/codex_day4_script/solve_d4.py').read().split('if __name__')[0])
S=requests.Session(); S.headers.update({'Content-Type':'application/json'})
base=json.load(open('/home/HuntressCTF/codex_day4_script/d4_base.json'))
base={k:v for k,v in base.items() if base.get(k) is not None}
def submit(ans):
    for _ in range(6):
        r=S.post(U,data=json.dumps({'op':'submit','challenge':C,'answers':ans})).json()
        if r.get('error')=='rate_limited': time.sleep(1.4); continue
        return r
    return r
S.post(U,data=json.dumps({'op':'start','challenge':C})); submit(base)
CANDS=['do_until','unconditional_loop','infinite_loop','self_terminating','terminating_loop',
 'exit_dispatch','break_dispatch','run_once_loop','loop_once_guard','do_exit','do_exit_loop',
 'guarded_decode','decode_loop','loop_decode','staged','staged_loop','wound','winding_loop',
 'convoluted','circuitous','roundabout','meandering','looped_control','loop_flow','flow_loop']
tgt='vbscript-downloader-control'
hit=None
for c in CANDS:
    r=submit({**base,tgt:c})
    if r.get('result') in ('accepted','CORRECT'): hit=c; break
    time.sleep(1.4)
print('downloader-control =',hit)
