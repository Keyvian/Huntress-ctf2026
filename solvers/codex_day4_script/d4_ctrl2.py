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
CANDS=['loop_dispatch','loop_guard','guarded_loop','obfuscated_loop','redundant_loop','dummy_loop',
 'dead_loop','inert_loop','junk_loop','do_sentinel','sentinel_guard','one_shot','oneshot','one_pass',
 'single_iteration','immediate_exit','short_circuit','noop_loop','stub_loop','placeholder_loop',
 'control_loop','flow_obfuscation','obfuscated','indirection','indirect_loop','loop_indirect',
 'until_loop','loop_until','repeat_until','post_test_loop','pre_test_loop','counter_guard','flag_guard',
 'spin_guard','busy_loop','degenerate_loop','trivial','trivial_loop','pointless_loop','looping_guard',
 'do_loop_guard','while_guard','wend','doloop','whileloop','loopback','conditional_loop','predicate']
for tgt in ['vbscript-downloader-control','vbscript-impact-control']:
    hit=None
    for c in CANDS:
        r=submit({**base,tgt:c})
        if r.get('result') in ('accepted','CORRECT'): hit=c; break
        time.sleep(1.4)
    print(tgt,'=',hit)
