import sys, json
sys.path.insert(0, '~/ctf')
from gm import GM

CH = 'binary-reverse-engineering-day-30-sha1-hulud'
g = GM()
j = g.get('?op=list&day=30').json()
for c in j['challenges']:
    if c.get('id') == CH:
        print('LIST', json.dumps(c, indent=1, ensure_ascii=False))
print('MSG', j.get('message'))
print('STATUS', json.dumps(g.status(CH), indent=1, ensure_ascii=False)[:6000])
