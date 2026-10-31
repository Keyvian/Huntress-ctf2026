import os, re, pefile, struct

X = os.path.expanduser('~/ctf/day30_extra/x/sha1-hulud.exe.bin')
d = open(X, 'rb').read()
pe = pefile.PE(data=d)
base = pe.OPTIONAL_HEADER.ImageBase
for e in pe.DIRECTORY_ENTRY_IMPORT:
    for i in e.imports:
        print('IMP', hex(i.address), e.dll.decode(), (i.name or b'').decode())

secs = {s.Name.rstrip(b'\0').decode(): s for s in pe.sections}

rd = secs['.rdata']
b = rd.get_data()
print('--- .rdata strings')
for m in re.finditer(rb'[\x20-\x7e]{5,}', b):
    s = m.group()
    print(hex(base + rd.VirtualAddress + m.start()), s[:160])

print('--- .xsobf')
xs = secs['.xsobf'].get_data()
print(xs[:0x1ad].hex())

print('--- tls dir')
if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
    t = pe.DIRECTORY_ENTRY_TLS.struct
    print(hex(t.StartAddressOfRawData), hex(t.EndAddressOfRawData), hex(t.AddressOfIndex),
          hex(t.AddressOfCallBacks), t.SizeOfZeroFill, t.Characteristics)
    a = t.AddressOfCallBacks - base
    for i in range(6):
        v = pe.get_qword_at_rva(a + 8 * i)
        print(' cb', hex(v))
        if not v:
            break
print('--- .gfids')
print(secs['.gfids'].get_data()[:0x80].hex())
print('--- _RDATA')
print(secs['_RDATA'].get_data()[:0x1f4].hex())
print('--- .data head')
print(secs['.data'].get_data()[:0x200].hex())
