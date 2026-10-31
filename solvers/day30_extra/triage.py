import os, hashlib, pyzipper, pefile, re, math, collections

ART = os.path.expanduser('~/ctf/day30_extra/art')
OUT = os.path.expanduser('~/ctf/day30_extra/x')
os.makedirs(OUT, exist_ok=True)
z = pyzipper.AESZipFile(os.path.join(ART, 'delivery0.bin'))
z.setpassword(b'infected')
for i in z.infolist():
    d = z.read(i.filename)
    p = os.path.join(OUT, os.path.basename(i.filename) + '.bin')
    open(p, 'wb').write(d)
    print(i.filename, len(d), hashlib.sha256(d).hexdigest())

d = open(os.path.join(OUT, 'sha1-hulud.exe.bin'), 'rb').read()
pe = pefile.PE(data=d)
print('machine', hex(pe.FILE_HEADER.Machine), 'subsys', pe.OPTIONAL_HEADER.Subsystem,
      'entry', hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint), 'imgbase', hex(pe.OPTIONAL_HEADER.ImageBase),
      'ts', pe.FILE_HEADER.TimeDateStamp)
print('dotnet dir', pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress, pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].Size)


def ent(b):
    if not b:
        return 0
    c = collections.Counter(b)
    return -sum(v / len(b) * math.log2(v / len(b)) for v in c.values())


for s in pe.sections:
    b = s.get_data()
    print(s.Name.rstrip(b'\0'), hex(s.VirtualAddress), hex(s.Misc_VirtualSize), hex(s.SizeOfRawData),
          hex(s.PointerToRawData), 'ent %.2f' % ent(b), hex(s.Characteristics))
if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    for e in pe.DIRECTORY_ENTRY_IMPORT:
        print(e.dll, [(i.name or b'').decode() for i in e.imports][:60])
if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
    for e in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        print('RES', e.name, e.id)
print('overlay', pe.get_overlay_data_start_offset(), len(d))
strs = re.findall(rb'[\x20-\x7e]{6,}', d)
print('nstrings', len(strs))
for s in strs[:220]:
    print(s[:120])
wide = re.findall(rb'(?:[\x20-\x7e]\x00){6,}', d)
print('nwide', len(wide))
for s in wide[:120]:
    print(s.decode('utf-16le')[:120])
