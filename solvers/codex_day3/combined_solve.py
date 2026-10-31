#!/usr/bin/env python3
import sys, re, json, time
sys.path.insert(0, '/home/HuntressCTF/codex_day3')
import solve_expansion as SE
exec(open('/home/HuntressCTF/codex_day3/exp_driver.py').read().split('SE.batch_decode = batch_decode_fixed')[0])
SE.batch_decode = batch_decode_fixed
from solve_table import gather, U
import requests
S = requests.Session()
CANDS = ['for_indirect', 'call_double', 'delayed', 'percent']
BASE = 'script-analysis-day-03-batch-expansion'

def submit(C, ans):
    for _ in range(3):
        r = S.post(U, json={'op': 'submit', 'challenge': C, 'answers': ans}).json()
        if r.get('error') == 'rate_limited':
            time.sleep(1.0); continue
        return r
    return r

def compute(C, ids):
    sets = sorted({int(m[1]) for x in ids if (m := re.match(r'set(\d+)\.', x))})
    out = {}
    if sets:
        for sn in sets:
            bb = S.get(U, params={'op': 'artifact', 'challenge': C, 'delivery': sn - 1}).content
            if bb[:2] != b'PK':
                bb = S.get(U, params={'op': 'artifact', 'challenge': C}).content
            aa, _ = SE.analyze(gather(bb))
            for k, v in aa.items():
                out['set%d.' % sn + k] = v
    else:
        out, _ = SE.analyze(gather(S.get(U, params={'op': 'artifact', 'challenge': C}).content))
    return {k: out[k] for k in ids if k in out}

def solve(mode, tries):
    C = BASE + ('/' + mode if mode != 'single_solve' else '')
    for whole in range(tries):
        t = time.time()
        r = S.post(U, json={'op': 'start' if whole == 0 else 'retry', 'challenge': C}).json()
        if 'answer_ids' not in r:
            r = S.post(U, json={'op': 'start', 'challenge': C}).json()
        if 'answer_ids' not in r:
            if r.get('error') == 'prerequisite_required':
                return ('LOCKED', None)
            time.sleep(1.2); continue
        ids = r['answer_ids']
        a = compute(C, ids)
        exp = [k for k in ids if k.endswith('-expansion') and k in a]
        base = {k: v for k, v in a.items() if k not in exp}
        r0 = submit(C, base)
        res0 = r0.get('result')
        if res0 == 'CORRECT':
            print(mode, 'SOLVED(base)', r0.get('flag'), flush=True); return ('CORRECT', r0.get('flag'))
        if res0 != 'accepted':
            print(mode, 'whole', whole, 'base', {k: r0.get(k) for k in ('result', 'remaining', 'error')}, flush=True)
            time.sleep(1.0); continue
        flag = None; done = False
        for k in exp:
            for cand in [a[k]] + [c for c in CANDS if c != a[k]]:
                rr = submit(C, {**base, k: cand})
                if rr.get('result') == 'CORRECT':
                    flag = rr.get('flag'); done = True; break
                if rr.get('result') == 'accepted':
                    base = {**base, k: cand}; break
            if done:
                break
        if not done:
            rf = submit(C, a)
            if rf.get('result') == 'CORRECT':
                flag = rf.get('flag'); done = True
            print(mode, 'whole', whole, 'remaining', rf.get('remaining'), 'el', round(time.time()-t, 2), flush=True)
        if done:
            print(mode, 'SOLVED', flag, 'el', round(time.time()-t, 2), flush=True)
            return ('CORRECT', flag)
        time.sleep(1.0)
    return ('UNSOLVED', None)

if __name__ == '__main__':
    print('=== time_trial ==='); st, f1 = solve('time_trial', 10); print('time_trial ->', st, f1)
    print('=== mastery ==='); sm, f2 = solve('mastery', 12); print('mastery ->', sm, f2)
