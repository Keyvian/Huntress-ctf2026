"""Inspect the post-integrity snapshot: which image regions the two sampled buffers hold, and how they compare to the file."""
import hashlib, pickle, struct, pefile

st = pickle.load(open("~/d30/hulud/snap_input.pkl", "rb"))
BASE = 0x140000000
HEAP = 0x20000000
STACK = 0x10000000
rbp = st["regs"]["rbp"]
mem = st["mem"]


def rd(a, n):
    for b, d in mem.items():
        if b <= a < b + len(d):
            return d[a - b:a - b + n]
    return b""


q = lambda a: struct.unpack("<Q", rd(a, 8))[0]
print("rbp %x" % rbp)
for off in (0x5e0, 0x600, 0x608, 0x4f0, 0x6d8, 0x3f0, 0x7b8, 0x1140, 0x1178, 0xf78, 0xf60, 0x7c0, 0x5d0):
    print("[rbp+%x] = %x" % (off, q(rbp + off)))
pe = pefile.PE("~/d30/hulud/x/sha1-hulud.exe")
img = bytes(pe.get_memory_mapped_image())
for nm, off_ptr, off_len in (("A", 0x608, 0x6d8), ("B", 0x600, 0x4f0)):
    p, n = q(rbp + off_ptr), q(rbp + off_len)
    d = rd(p, n)
    print(nm, "ptr %x len %x got %x sha1 %s head %s" % (p, n, len(d), hashlib.sha1(d).hexdigest()[:16], d[:24].hex()))
    if n and n < 0x200000:
        for s in pe.sections:
            sec = s.get_data()
            if d[:64] and d[:64] in sec:
                print("   head found in", s.Name, "at", hex(sec.find(d[:64])))
        idx = img.find(d[:64])
        print("   head in image at", hex(idx))
        if idx >= 0:
            orig = img[idx:idx + n]
            diffs = [i for i in range(min(len(orig), len(d))) if orig[i] != d[i]]
            print("   diffs vs file image:", len(diffs), [hex(x) for x in diffs[:20]])
            if diffs:
                print("   first diff bytes", d[diffs[0]:diffs[0] + 16].hex(), orig[diffs[0]:diffs[0] + 16].hex())
