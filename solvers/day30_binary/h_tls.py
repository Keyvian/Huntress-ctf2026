"""List TLS callbacks and the global at 0x98008; show every reference to that global."""
import struct, pefile, capstone

P = "~/d30/hulud/x/sha1-hulud.exe"
pe = pefile.PE(P)
BASE = pe.OPTIONAL_HEADER.ImageBase
img = bytes(pe.get_memory_mapped_image())
t = pe.DIRECTORY_ENTRY_TLS.struct
print("TLS start %x end %x index %x callbacks %x" % (t.StartAddressOfRawData, t.EndAddressOfRawData, t.AddressOfIndex, t.AddressOfCallBacks))
cb = t.AddressOfCallBacks - BASE
cbs = []
while True:
    v = struct.unpack("<Q", img[cb:cb + 8])[0]
    if not v:
        break
    cbs.append(v - BASE)
    cb += 8
print("callbacks", [hex(x) for x in cbs])
print("0x98000:", img[0x98000:0x98020].hex())
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
pd = [x for x in pe.sections if x.Name.startswith(b".pdata")][0]
data = pd.get_data()[:pd.Misc_VirtualSize]
for i in range(0, len(data), 12):
    a, b, _ = struct.unpack("<III", data[i:i + 12])
    if not a:
        continue
    for ins in md.disasm(img[a:b], a):
        for op in ins.operands:
            if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                tgt = ins.address + ins.size + op.mem.disp
                if 0x98000 <= tgt < 0x98020:
                    print("ref %x -> %x (fn %x) %s %s" % (ins.address, tgt, a, ins.mnemonic, ins.op_str))
