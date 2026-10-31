#!/usr/bin/env python3
# Mastery solver: compute per-set answers with the patched classifier, bank the
# confident fields, then brute-force each expansion field's label over the 4
# candidates (the correct one banks) until remaining hits 0 -> CORRECT.
import sys, re, json, time
sys.path.insert(0, '/home/HuntressCTF/codex_day3')
import solve_expansion as SE
exec(open('/home/HuntressCTF/codex_day3/exp_driver.py').read().split('SE.batch_decode = batch_decode_fixed')[0])
SE.batch_decode = batch_decode_fixed
from solve_table import gather, U
import requests
S = requests.Session()
C = 'script-analysis-day-03-batch-expansion/mastery'
CANDS = ['for_indirect', 'call_double', 'delayed', 'percent']

def submit(ans):
    for _ in range(3):
        r = S.post(U, json={'op': 'submit', 'challenge': C, 'answers': ans}).json()
        if r.get('error') == 'rate_limited':
            time.sleep(1.2); continue
        return r
    return r

for whole in range(8):
    t = time.time()
    r = S.post(U, json={'op': 'start' if whole == 0 else 'retry', 'challenge': C}).json()
    if 'answer_ids' not in r:
        r = S.post(U, json={'op': 'start', 'challenge': C}).json()
    if 'answer_ids' not in r:
        print('whole', whole, 'cannot start:', {k: r.get(k) for k in ('error', 'result')}); time.sleep(1.5); continue
    ids = r['answer_ids']
    sets = sorted({int(m[1]) for x in ids if (m := re.match(r'set(\d+)\.', x))})
    allans = {}
    if sets:
        for sn in sets:
            bb = S.get(U, params={'op': 'artifact', 'challenge': C, 'delivery': sn - 1}).content
            if bb[:2] != b'PK':
                bb = S.get(U, params={'op': 'artifact', 'challenge': C}).content
            aa, _ = SE.analyze(gather(bb))
            for k, v in aa.items():
                allans['set%d.' % sn + k] = v
    else:
        allans, _ = SE.analyze(gather(S.get(U, params={'op': 'artifact', 'challenge': C}).content))
    a = {k: allans[k] for k in ids if k in allans}
    exp = [k for k in ids if k.endswith('-expansion') and k in a]
    base = {k: v for k, v in a.items() if k not in exp}
    r0 = submit(base)
    print('whole', whole, 'sets', sets, 'ids', len(ids), 'computed', len(a),
          'base:', {k: r0.get(k) for k in ('result', 'remaining', 'error')}, 'el', round(time.time()-t, 2), flush=True)
    if r0.get('result') == 'CORRECT':
        print('SOLVED', r0.get('flag')); break
    if r0.get('result') != 'accepted':
        time.sleep(1.5); continue
    done = False
    for k in exp:
        order = [a[k]] + [c for c in CANDS if c != a[k]]
        for cand in order:
            rr = submit({**base, k: cand})
            res = rr.get('result')
            if res == 'CORRECT':
                print('SOLVED', rr.get('flag'), 'el', round(time.time()-t, 2)); done = True; break
            if res == 'accepted':
                base = {**base, k: cand}; break
        if done:
            break
    if done:
        break
    # final full submit in case all expansion banked
    rf = submit(a)
    print('   final', {k: rf.get(k) for k in ('result', 'remaining', 'flag')}, 'el', round(time.time()-t, 2), flush=True)
    if rf.get('result') == 'CORRECT':
        print('SOLVED', rf.get('flag')); break
    time.sleep(1.5)
