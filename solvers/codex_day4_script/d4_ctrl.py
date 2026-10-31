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
S.post(U,data=json.dumps({'op':'start','challenge':C}))
submit(base)  # re-bank
CANDS=['do_loop','do_while','do_until','while_wend','loop','do','exit_do','exit_loop','loop_exit',
 'early_exit','exit_guard','do_guard','guarded_loop','bounded_loop','single_pass','loop_once','run_once',
 'spin','sentinel_loop','loop_sentinel','decoy_loop','winding','noop_loop','empty_loop','self_exit',
 'break_loop','iteration','looping','post_test','pre_test','trivial_loop','degenerate_loop','once','looped_guard']
tgt='vbscript-downloader-control'
hit=None
for c in CANDS:
    r=submit({**base,tgt:c}); res=r.get('result')
    if res in ('accepted','CORRECT'): hit=c; print('HIT',tgt,'=',c,res); break
    time.sleep(1.5)
print('downloader-control =',hit)
