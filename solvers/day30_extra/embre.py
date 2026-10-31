import os, re, pefile, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

X = os.path.expanduser('~/ctf/day30_extra/x/sha1-hulud.exe.bin')
d = open(X, 'rb').read()
pe = pefile.PE(data=d)
base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_64)
text = next(s for s in pe.sections if s.Name.startswith(b'.text'))
code = text.get_data()
tva = base + text.VirtualAddress


def rd(va, n):
    return pe.get_data(va - base, n)


# xrefs: scan .text for call rel32 to a given target
def callers(tgt):
    out = []
    for i in range(len(code) - 5):
        if code[i] == 0xE8:
            r = struct.unpack_from('<i', code, i + 1)[0]
            if tva + i + 5 + r == tgt:
                out.append(tva + i)
    return out


def rip_refs(tgt):
    # lea/mov reg,[rip+disp32] style: any 4-byte disp resolving to tgt with a 7-byte insn
    out = []
    for i in range(3, len(code) - 4):
        r = struct.unpack_from('<i', code, i)[0]
        if tva + i + 4 + r == tgt and code[i - 2] in (0x8D, 0x8B):
            out.append(tva + i - 3)
    return out


for name, tgt in [('xor-dec', 0x14005dc8a), ('xsobf-eq', 0x14003bca2), ('sectfind', 0x14005dbbb),
                  ('665bf', 0x1400665bf), ('66aac', 0x140066aac), ('veh-reg', 0x140065d51),
                  ('blob', 0x14003bee8), ('63f9d', 0x140063f9d), ('63bc8', 0x140063bc8)]:
    print(name, [hex(x) for x in callers(tgt)][:40])
for name, tgt in [('xsobf-eq-ref', 0x14003bca2), ('veh-ref', 0x140065baa), ('ae0', 0x140098ae0), ('sect-str', 0x1400884d0)]:
    print(name, [hex(x) for x in rip_refs(tgt)][:40])

# for each xor-dec caller print the preceding 40 instructions' pointers to rdata + length
for c in callers(0x14005dc8a):
    start = c - 0x70
    ins = list(md.disasm(rd(start, 0x78), start))
    ptrs = []
    lens = []
    for it in ins:
        m = re.search(r'rip \+ 0x([0-9a-f]+)', it.op_str)
        if m:
            t = it.address + it.size + int(m.group(1), 16)
            if 0x14007f000 <= t < 0x140098000:
                ptrs.append(t)
        m = re.match(r'(.*), 0x([0-9a-f]+)$', it.op_str)
        if it.mnemonic == 'push':
            try:
                lens.append(int(it.op_str, 16))
            except Exception:
                pass
        elif m and it.mnemonic == 'mov' and int(m.group(2), 16) < 0x400:
            lens.append(int(m.group(2), 16))
    print(hex(c), [hex(p) for p in ptrs[-2:]], lens[-3:])
    if len(ptrs) >= 2 and lens:
        for ln in set(lens[-3:]):
            ct, key = rd(ptrs[-2], ln), rd(ptrs[-1], ln)
            pt = bytes(a ^ b for a, b in zip(ct, key))
            print('   len', ln, repr(pt))
