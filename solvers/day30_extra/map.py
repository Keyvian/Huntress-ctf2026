import os, re, pefile, collections
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

W = os.path.expanduser('~/ctf/day30_extra/')
d = open(W + 'x/sha1-hulud.exe.bin', 'rb').read()
pe = pefile.PE(data=d)
base = pe.OPTIONAL_HEADER.ImageBase
iat = {}
for e in pe.DIRECTORY_ENTRY_IMPORT:
    for i in e.imports:
        iat[i.address] = (i.name or b'').decode()
md = Cs(CS_ARCH_X86, CS_MODE_64)
S, E = 0x14003c38a, 0x14005a24f
ins = list(md.disasm(pe.get_data(S - base, E - S), S))
print('count', len(ins))
with open(W + 'full.txt', 'w') as f:
    for it in ins:
        ann = ''
        m = re.search(r'rip ([+-]) 0x([0-9a-f]+)', it.op_str)
        if m:
            off = int(m.group(2), 16)
            t = it.address + it.size + (off if m.group(1) == '+' else -off)
            ann = ' ; %#x %s' % (t, iat.get(t, ''))
        f.write('%x: %-8s %s%s\n' % (it.address, it.mnemonic, it.op_str, ann))

calls = collections.Counter()
for it in ins:
    if it.mnemonic == 'call':
        calls[it.op_str] += 1
print(calls.most_common(70))
# ordered list of data refs + non-hot calls
hot = {k for k, v in calls.items() if v > 20}
with open(W + 'skeleton.txt', 'w') as f:
    for it in ins:
        s = it.op_str
        m = re.search(r'rip ([+-]) 0x([0-9a-f]+)', s)
        out = None
        if m:
            off = int(m.group(2), 16)
            t = it.address + it.size + (off if m.group(1) == '+' else -off)
            if t in iat:
                if iat[t] not in ('VirtualProtect', 'GetCurrentThreadId', 'GetThreadContext', 'GetCurrentThread'):
                    out = iat[t]
            elif 0x14007f000 <= t < 0x140098000:
                out = 'RDATA %#x' % t
            elif 0x140098000 <= t < 0x14009a000 and t not in (0x140098a8d, 0x140098bb8, 0x140098ae0, 0x140098a8c, 0x140098a8e, 0x140098000):
                out = 'DATA %#x' % t
            elif t < 0x14007f000 and it.mnemonic == 'lea' and t not in (0x140001080, 0x1400641b3):
                out = 'CODE %#x' % t
        elif it.mnemonic == 'call' and s not in hot:
            out = 'CALL ' + s
        elif it.mnemonic == 'movabs':
            out = 'IMM ' + s.split(', ')[1]
        elif it.mnemonic in ('rdrand', 'cpuid', 'ud2', 'int3', 'jmp') and it.mnemonic != 'jmp':
            out = it.mnemonic
        elif it.mnemonic == 'jmp' and s.startswith('r'):
            out = 'INDIRECT ' + s
        if out:
            f.write('%x %s %s\n' % (it.address, it.mnemonic, out))
