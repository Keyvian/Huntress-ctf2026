"""Print an instruction trace saved by h_emu.py --tracefn: h_trdis.py <pickle> [out.txt]."""
import pickle, sys
import capstone

tr = pickle.load(open(sys.argv[1], "rb"))
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
out = open(sys.argv[2], "w") if len(sys.argv) > 2 else sys.stdout
for a, b in tr:
    i = next(md.disasm(b, a), None)
    out.write("%6x  %-8s %s\n" % (a, i.mnemonic if i else "??", i.op_str if i else b.hex()))
