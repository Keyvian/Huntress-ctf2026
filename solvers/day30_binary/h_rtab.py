"""Per-round table of a reduced protected SHA-1 routine: t, function class, K, rotations. h_rtab.py <rXXXX.txt>"""
import re, sys

t = 0
rows = []
for l in open(sys.argv[1]):
    m = re.search(r"add (\w+), (0x5a827999|0x6ed9eba1|0x8f1bbcdc|0xca62c1d6)", l)
    if not m:
        continue
    k = m.group(2)
    body = l.split(" ", 1)[1]
    if " not " in body:
        f = "Ch"
    elif re.search(r"\bor \w+, \w+|\band \w+, \w+", body):
        f = "Maj"
    else:
        f = "Par"
    rots = re.findall(r"rol (\w+), (0x[0-9a-f]+|\d+)", body)
    rv = sorted({int(x, 0) for _, x in rots})
    rows.append((t, f, k, rv))
    t += 1
prev = None
for r in rows:
    key = r[1:3] + (tuple(r[3]),)
    if key != prev:
        print(r)
        prev = key
print("rounds", len(rows))
