"""Search the 'layered' puzzle transform on a saved huntress_puzzle.json: which composition of layers gives exactly ANS-<16 HEX>.
usage: layer30.py <huntress_puzzle.json>"""
import sys, re, json, base64

ANS = re.compile(r"ANS-[0-9A-F]{16}")
p = json.load(open(sys.argv[1]))
print(p)
b = base64.b64decode(p["data"])
k = p["key"]
print(b.hex(), len(b), k)
hits = []
for s in range(256):
    x = bytes(c ^ ((k + s * i) & 255) for i, c in enumerate(b))
    r = bytes(c ^ ((k + s * i) & 255) for i, c in enumerate(b[::-1]))
    su = bytes((c - k - s * i) & 255 for i, c in enumerate(b))
    ru = bytes((c - k - s * i) & 255 for i, c in enumerate(b[::-1]))
    ad = bytes((c + k + s * i) & 255 for i, c in enumerate(b))
    ra = bytes((c + k + s * i) & 255 for i, c in enumerate(b[::-1]))
    for lab, v in (("xor_i", x), ("xor_i>rev", x[::-1]), ("rev>xor_i", r), ("rev>xor_i>rev", r[::-1]),
                   ("sub_i", su), ("sub_i>rev", su[::-1]), ("rev>sub_i", ru), ("add_i", ad), ("add_i>rev", ad[::-1]), ("rev>add_i", ra)):
        t = v.decode("latin1")
        if ANS.fullmatch(t):
            hits.append((s, lab, t))
print("hits", hits)
