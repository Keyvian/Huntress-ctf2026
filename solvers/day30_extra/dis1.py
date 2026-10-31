import os, sys, pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

X = os.path.expanduser('~/ctf/day30_extra/x/sha1-hulud.exe.bin')
d = open(X, 'rb').read()
pe = pefile.PE(data=d, fast_load=False)
base = pe.OPTIONAL_HEADER.ImageBase
iat = {}
for e in pe.DIRECTORY_ENTRY_IMPORT:
    for i in e.imports:
        iat[i.address] = (i.name or b'').decode()
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = False


def rd(va, n):
    return pe.get_data(va - base, n)


def dis(va, n, stop_ret=True):
    code = rd(va, n)
    rets = 0
    for ins in md.disasm(code, va):
        ann = ''
        s = ins.op_str
        if 'rip' in s:
            import re
            m = re.search(r'rip ([+-]) 0x([0-9a-f]+)', s)
            if m:
                off = int(m.group(2), 16)
                t = ins.address + ins.size + (off if m.group(1) == '+' else -off)
                ann = ' ; -> %#x %s' % (t, iat.get(t, ''))
        print('%x: %-8s %s%s' % (ins.address, ins.mnemonic, ins.op_str, ann))
        if stop_ret and ins.mnemonic == 'ret':
            rets += 1
            if rets >= stop_ret:
                return


va = int(sys.argv[1], 16)
n = int(sys.argv[2], 16)
dis(va, n, int(sys.argv[3]) if len(sys.argv) > 3 else 1)
