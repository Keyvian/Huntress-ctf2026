"""SHA1-Hulud recon: unusual PE sections, printable strings in .rdata/.data."""
import pefile, re, sys

p = "~/d30/hulud/x/sha1-hulud.exe"
pe = pefile.PE(p)
for s in pe.sections:
    if s.Name.rstrip(b"\x00") in (b".xsobf", b".gfids", b"_RDATA", b".tls"):
        print(s.Name, s.get_data().hex())
for name in (b".rdata", b".data"):
    s = [x for x in pe.sections if x.Name.startswith(name)][0]
    d = s.get_data()
    st = re.findall(rb"[\x20-\x7e]{5,}", d)
    print(name, len(st))
    for x in st:
        print(" ", x.decode()[:200])
