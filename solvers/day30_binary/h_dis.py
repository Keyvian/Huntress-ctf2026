"""SHA1-Hulud disassembly helper.
h_dis.py xrefs <import substring,...>  -> pdata functions that reference these IAT entries
h_dis.py fn <rva-hex> [...]            -> disassemble the pdata function(s) holding the rva
h_dis.py refs <rva-hex>                -> instructions whose rip-relative operand lands on the rva
h_dis.py funcs                         -> pdata function list with sizes"""
import sys, struct, bisect
import pefile, capstone

P = "~/d30/hulud/x/sha1-hulud.exe"
pe = pefile.PE(P)
BASE = pe.OPTIONAL_HEADER.ImageBase
img = pe.get_memory_mapped_image()
IAT = {}
for e in pe.DIRECTORY_ENTRY_IMPORT:
    for i in e.imports:
        IAT[i.address - BASE] = (e.dll.decode() + "!" + (i.name.decode() if i.name else str(i.ordinal)))
sec = {s.Name.rstrip(b"\x00").decode(): s for s in pe.sections}
pd = sec[".pdata"]
pdata = pd.get_data()[:pd.Misc_VirtualSize]
F = []
for i in range(0, len(pdata), 12):
    a, b, u = struct.unpack("<III", pdata[i:i + 12])
    if a:
        F.append((a, b, u))
F.sort()
ST = [x[0] for x in F]
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True


def fn_of(rva):
    i = bisect.bisect_right(ST, rva) - 1
    if i >= 0 and F[i][0] <= rva < F[i][1]:
        return F[i]
    return None


def annot(ins):
    out = []
    for op in ins.operands:
        t = None
        if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
            t = ins.address + ins.size + op.mem.disp
        elif op.type == capstone.x86.X86_OP_IMM and ins.mnemonic in ("call", "jmp"):
            t = op.imm
        if t is None:
            continue
        if t in IAT:
            out.append(IAT[t])
        else:
            s = None
            for sn, se in sec.items():
                if se.VirtualAddress <= t < se.VirtualAddress + se.Misc_VirtualSize:
                    s = sn
            if s in (".rdata", ".data", ".xsobf"):
                raw = img[t:t + 48]
                txt = raw.split(b"\x00")[0]
                out.append("%s %r" % (s, txt[:48]) if all(32 <= c < 127 for c in txt[:48]) and len(txt) > 3 else "%s %s" % (s, raw[:16].hex()))
    return " ; " + " | ".join(out) if out else ""


def dis(f):
    a, b, _ = f
    print("--- fn %#x..%#x (%d)" % (a, b, b - a))
    for ins in md.disasm(bytes(img[a:b]), a):
        print("%6x  %-8s %s%s" % (ins.address, ins.mnemonic, ins.op_str, annot(ins)))


def scan(fn):
    for f in F:
        a, b, _ = f
        for ins in md.disasm(bytes(img[a:b]), a):
            r = fn(ins)
            if r:
                yield f, ins


def target(ins):
    for op in ins.operands:
        if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
            return ins.address + ins.size + op.mem.disp
        if op.type == capstone.x86.X86_OP_IMM and ins.mnemonic in ("call", "jmp") or ins.mnemonic[0] == "j" and op.type == capstone.x86.X86_OP_IMM:
            return op.imm
    return None


cmd = sys.argv[1]
if cmd == "funcs":
    for a, b, _ in F:
        print("%x %d" % (a, b - a))
elif cmd == "fn":
    seen = set()
    for x in sys.argv[2:]:
        f = fn_of(int(x, 16))
        if f and f[0] not in seen:
            seen.add(f[0]); dis(f)
        elif not f:
            print("no pdata fn for", x)
elif cmd == "xrefs":
    want = sys.argv[2].split(",")
    t = {a: n for a, n in IAT.items() if any(w in n for w in want)}
    for f, ins in scan(lambda i: target(i) in t):
        print("%x (fn %x size %d) %s %s -> %s" % (ins.address, f[0], f[1] - f[0], ins.mnemonic, ins.op_str, t[target(ins)]))
elif cmd == "refs":
    want = set(int(x, 16) for x in sys.argv[2:])
    for f, ins in scan(lambda i: target(i) in want):
        print("%x (fn %x size %d) %s %s" % (ins.address, f[0], f[1] - f[0], ins.mnemonic, ins.op_str))
