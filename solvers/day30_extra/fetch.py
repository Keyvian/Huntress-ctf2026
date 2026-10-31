import sys, json, os, hashlib, time
sys.path.insert(0, '~/ctf')
from gm import GM

CH = 'binary-reverse-engineering-day-30-sha1-hulud'
ART = os.path.expanduser('~/ctf/day30_extra/art')
os.makedirs(ART, exist_ok=True)
g = GM()

for attempt in range(6):
    r = g.start(CH)
    if r.get('error') not in ('rate_limited',):
        break
    time.sleep(2 ** attempt)

# drop the long boilerplate guidance from the display
show = {k: v for k, v in r.items() if k != 'guidance'}
print('START', json.dumps(show, indent=1, ensure_ascii=False)[:6000])

blob = g.artifact(CH)
p = os.path.join(ART, 'delivery0.bin')
open(p, 'wb').write(blob)
print('ARTIFACT', len(blob), hashlib.sha256(blob).hexdigest(), blob[:64])
