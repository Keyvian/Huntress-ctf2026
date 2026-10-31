"""h_rng.py <start-hex> <end-hex>: linear disassembly of an RVA range; h_rng.py ent: 4 KiB entropy map of .text."""
import sys, math
sys.argv_saved = list(sys.argv)
import pefile, capstone

P = "~/d30/hulud/x/sha1-hulud.exe"
pe = pefile.PE(P)
img = pe.get_memory_mapped_image()
if sys.argv[1] == "ent":
    t = [s for s in pe.sections if s.Name.startswith(b".text")][0]
    for a in range(0x1000, 0x7f000, 0x4000):
        d = bytes(img[a:a + 0x4000])
        c = [0] * 256
        for x in d:
            c[x] += 1
        e = -sum(v / len(d) * math.log2(v / len(d)) for v in c if v)
        print("%06x %.2f" % (a, e))
else:
    a, b = int(sys.argv[1], 16), int(sys.argv[2], 16)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    for i in md.disasm(bytes(img[a:b]), a):
        print("%6x  %-8s %s" % (i.address, i.mnemonic, i.op_str))
