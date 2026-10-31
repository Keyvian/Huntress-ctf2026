import sys, json
sys.path.insert(0, '~/ctf')
from gm import GM

LANES = ('warmups', 'metadata-forensics', 'mobile-android', 'script-analysis',
         'binary-reverse-engineering', 'web-exploitation')
SKIP = ('welcome-robots', 'read-the-rules')


def items(j):
    if isinstance(j, list):
        return j
    return j.get('challenges') or j.get('items') or []


g = GM()
for q in ('?op=list&day=30', '?op=list&all=true'):
    r = g.get(q)
    try:
        j = r.json()
    except Exception:
        print(q, 'non-json', r.status_code, r.text[:300])
        continue
    its = items(j)
    print(q, 'status', r.status_code, 'count', len(its))
    if isinstance(j, dict):
        print('  top keys', [k for k in j.keys()][:20])
    days = {}
    extras = []
    for c in its:
        cid = c.get('id') or c.get('challenge') or c.get('slug') or ''
        days[c.get('day')] = days.get(c.get('day'), 0) + 1
        if not cid.startswith(LANES) and cid.split('/')[0] not in SKIP:
            extras.append(c)
    print('  days', sorted(days.items(), key=lambda kv: str(kv[0]))[-6:])
    print('  non-lane ids:', json.dumps(extras, indent=1)[:3000])
    if '30' in q:
        for c in its[:40]:
            print('   ', c.get('id'), c.get('day'), c.get('title') or c.get('name'), c.get('status'))
