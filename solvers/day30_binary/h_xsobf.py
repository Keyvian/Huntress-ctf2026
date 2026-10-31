"""Decode .xsobf strings: each descriptor is (ptr, len, tag); keystream per h_dis fn 6397c."""
import re, sys, pefile

M = (1 << 64) - 1
pe = pefile.PE("~/d30/hulud/x/sha1-hulud.exe")
img = pe.get_memory_mapped_image()


def rol(x, n):
    return ((x << n) | (x >> (64 - n))) & M


def dec(ptr, n, tag):
    r8 = 0x5d2e9c47a1b386f0 ^ rol(tag, 0x11)
    r9, out = 0, bytearray()
    for i in range(n):
        r15 = r9 ^ r8
        r12 = ((r15 >> 0x1d) ^ r15)
        r12 = (r12 * 0x41169ddc6c156db1) & M
        r15 = (r12 >> 0x1b) ^ r12
        r15 = (r15 * 0xa3d1f5bb9847a411) & M
        k = ((r15 >> 0x37) ^ (r15 >> 0x18)) & 0xff if False else (((r15 >> 0x37) & 0xffffffff) ^ ((r15 & 0xffffffff) >> 0x18)) & 0xff
        out.append(k ^ img[ptr + i])
        r9 = (r9 + 0x65767ac2ba816c3) & M
    return bytes(out)


lines = open(sys.argv[1]).read().splitlines()
ptrs = []
for i, l in enumerate(lines):
    m = re.search(r"lea\s+\w+, \[rip \+ 0x([0-9a-f]+)\] ; \.xsobf", l)
    if not m:
        continue
    addr = int(l.split()[0], 16)
    ln = re.search(r"^\s*[0-9a-f]+\s+lea\s+\w+, \[rip \+ 0x([0-9a-f]+)\]", l)
    # instruction length is 7 for lea r64,[rip+disp32]
    t = addr + 7 + int(m.group(1), 16)
    tag = None
    for j in range(i + 1, min(i + 10, len(lines))):
        mm = re.search(r"mov\s+\w+, (0x[0-9a-f]{8})\b", lines[j])
        if mm and int(mm.group(1), 16) >> 28 == 0xc:
            tag = int(mm.group(1), 16); break
    ptrs.append((addr, t, tag))
for addr, t, tag in ptrs:
    if tag is None:
        print("%x -> %x tag None" % (addr, t)); continue
    d = dec(t, 72, tag)
    n = 0
    while n < len(d) and 32 <= d[n] < 127:
        n += 1
    print("%x -> %x tag %08x len~%d %r" % (addr, t, tag, n, d[:n]))
