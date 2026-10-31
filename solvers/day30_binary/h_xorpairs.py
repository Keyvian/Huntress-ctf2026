"""Decode every embre xor pair: calls to 0x5dc8a get a [ptr,len,ptr,len] slice pair built in the lines just before."""
import re, sys, pefile

pe = pefile.PE("~/d30/hulud/x/sha1-hulud.exe")
img = pe.get_memory_mapped_image()
lines = open(sys.argv[1]).read().splitlines()
TARGET = sys.argv[2] if len(sys.argv) > 2 else "0x5dc8a"
for i, l in enumerate(lines):
    if "call     " + TARGET not in l:
        continue
    addr = int(l.split()[0], 16)
    ptrs, regs, lens = [], {}, []
    for j in range(max(0, i - 24), i):
        s = lines[j]
        m = re.search(r"^\s*([0-9a-f]+)\s+lea\s+(\w+), \[rip ([+-]) 0x([0-9a-f]+)\]", s)
        if m:
            a = int(m.group(1), 16)
            t = a + 7 + (int(m.group(4), 16) * (1 if m.group(3) == "+" else -1))
            ptrs.append(t)
        m = re.search(r"push\s+(0x[0-9a-f]+|\d+)$", s)
        if m:
            lens.append(int(m.group(1), 0))
        m = re.search(r"mov\s+\w+, (0x[0-9a-f]+)$", s)
        if m and int(m.group(1), 16) < 0x400:
            lens.append(int(m.group(1), 16))
        m = re.search(r"mov\s+qword ptr \[\w+ \+ (?:8|0x18)\], (0x[0-9a-f]+)$", s)
        if m:
            lens.append(int(m.group(1), 16))
    if len(ptrs) < 2 or not lens:
        print("%x: ?? ptrs=%s lens=%s" % (addr, [hex(p) for p in ptrs], lens)); continue
    a, b = ptrs[-2], ptrs[-1]
    n = lens[-1]
    d = bytes(img[a + k] ^ img[b + k] for k in range(n))
    print("%x: %x ^ %x len %d -> %r" % (addr, a, b, n, d))
