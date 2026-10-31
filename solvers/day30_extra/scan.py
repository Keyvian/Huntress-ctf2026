import os, re, pefile, collections
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

W = os.path.expanduser('~/ctf/day30_extra/')
d = open(W + 'x/sha1-hulud.exe.bin', 'rb').read()
pe = pefile.PE(data=d)
base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.skipdata = True

# user code = pdata-known function ranges, so linear sweep resyncs at each function
funcs = sorted((e.struct.BeginAddress + base, e.struct.EndAddress + base) for e in pe.DIRECTORY_ENTRY_EXCEPTION)
print('pdata funcs', len(funcs), hex(funcs[0][0]), hex(funcs[-1][1]))
# the protected block has no pdata coverage?
cov = [(a, b) for a, b in funcs if a < 0x14003ab80]
print('in block', len(cov), [(hex(a), hex(b)) for a, b in cov[:10]])

SPECIAL = {'rdtsc', 'rdtscp', 'cpuid', 'int3', 'ud2', 'syscall', 'sysenter', 'in', 'out', 'pushfq', 'popfq', 'int',
           'rdrand', 'rdseed', 'xgetbv', 'sgdt', 'sidt', 'str', 'smsw', 'rdpmc', 'hlt', 'iretq', 'pushf', 'popf'}
hits = collections.defaultdict(list)
for s, e in [(0x140001080, 0x14003ab80), (0x14003ab80, 0x14007f000)]:
    pos = s
    code = pe.get_data(s - base, e - s)
    ins = md.disasm(code, s)
    for it in ins:
        if it.mnemonic in SPECIAL:
            hits[it.mnemonic].append(it.address)
for k, v in sorted(hits.items()):
    print(k, len(v), [hex(x) for x in v[:24]])
