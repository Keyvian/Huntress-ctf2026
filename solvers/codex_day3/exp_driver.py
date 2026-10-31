#!/usr/bin/env python3
# Driver: reuse Codex's Expansion Pack solver but with a corrected, name-agnostic
# batch_decode (adds the `percent` expansion form + name-agnostic control/expansion).
import sys, re, json
sys.path.insert(0, '/home/HuntressCTF/codex_day3')
import solve_expansion as SE

def batch_decode_fixed(s):
    # --- config dict: Codex's fragment parsing (vars ending 0-3), assert softened ---
    vals = {}
    for line in s.splitlines():
        m = re.match(r'\s*set\s+"?([A-Za-z_][A-Za-z_0-9]*[0-3])=(.*)', line, re.I)
        if m:
            v = m[2]
            if line.strip().lower().startswith('set "'):
                v = v.split('"', 1)[0]
            vals[m[1].lower()] = v.replace('^|', '|')
    text = ''.join(v for k, v in sorted(vals.items(), key=lambda x: int(x[0][-1])))
    cfg = dict(x.split('=', 1) for x in text.split('|') if '=' in x)

    # --- recovery region only: after the separator, minus decoy/plan trailers ---
    region = s.split(':HUNTRESS_SEPARATOR_DONE', 1)[-1]
    region = region.split(':HUNTRESS_UNUSED', 1)[0].split(':HUNTRESS_PLAN', 1)[0]

    # --- expansion form (priority: for-loop > call-double > echo operator) ---
    if re.search(r'for\s+%%\w+\s+in\s*\([^)]*\)\s*do\s+call\s+set', region, re.I):
        exp = 'for_indirect'
    elif re.search(r'(?im)^\s*call\s+set\s+"?[A-Za-z_]\w*=[^\n]*%%', region):
        exp = 'call_double'
    elif re.search(r'echo[^\n]*![A-Za-z_]\w*!', region):
        exp = 'delayed'
    elif re.search(r'echo[^\n]*%[A-Za-z_]\w*%', region):
        exp = 'percent'
    else:
        exp = 'delayed'

    # --- control form (name-agnostic), restricted to the recovery region ---
    if re.search(r'(?im)\bcall\s+:', region):
        ctrl = 'call_subroutine'
    elif re.search(r'(?im)\bif\s+defined\b', region):
        ctrl = 'if_guard'
    elif re.search(r'(?im)\bgoto\s+:', region):
        ctrl = 'goto_dispatch'
    elif re.search(r'(?im)\bif\s+errorlevel\b', region):
        ctrl = 'errorlevel_guard'
    else:
        ctrl = 'direct'
    return cfg, exp, ctrl

SE.batch_decode = batch_decode_fixed  # analyze() resolves batch_decode from SE globals

import expansion_fast  # imports after patch; its analyze() uses the patched batch_decode
expansion_fast.run(sys.argv[1] if len(sys.argv) > 1 else 'time_trial')
