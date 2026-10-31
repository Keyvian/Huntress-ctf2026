"""Decode adjacent .rdata XOR pairs (data immediately followed by an equal-length key) referenced by main."""
import re, sys, pefile

pe = pefile.PE("~/d30/hulud/x/sha1-hulud.exe")
img = pe.get_memory_mapped_image()
refs = []
for l in open(sys.argv[1]):
    m = re.search(r"^\s*([0-9a-f]+)\s+lea\s+\w+, \[rip \+ 0x([0-9a-f]+)\] ; \.rdata", l)
    if m:
        a = int(m.group(1), 16)
        refs.append((a, a + 7 + int(m.group(2), 16)))
seen = set()
for i in range(len(refs) - 1):
    a0, x = refs[i]
    for j in range(i + 1, min(i + 4, len(refs))):
        a1, y = refs[j]
        n = abs(y - x)
        if 1 <= n <= 96:
            p, q = min(x, y), max(x, y)
            d = bytes(img[p + k] ^ img[q + k] for k in range(n))
            pr = sum(32 <= c < 127 for c in d)
            if pr == n and (p, n) not in seen:
                seen.add((p, n))
                print("%x: %x len %d %r" % (a0, p, n, d))
