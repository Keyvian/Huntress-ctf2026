import sys, zipfile, struct, re, pefile
zb = open(sys.argv[1], "rb").read()
print("zip len", len(zb), "PK local headers at", [m.start() for m in re.finditer(rb"PK\x03\x04", zb)][:20])
print("central dirs", [m.start() for m in re.finditer(rb"PK\x01\x02", zb)][:20], "eocd", [m.start() for m in re.finditer(rb"PK\x05\x06", zb)])
z = zipfile.ZipFile(sys.argv[1])
print("comment", z.comment)
for i in z.infolist():
    print(i.filename, i.file_size, i.compress_size, i.extra, i.comment)
name = sys.argv[2] if len(sys.argv) > 2 else z.namelist()[0]
d = z.read(name)
e_lfanew = struct.unpack_from("<I", d, 0x3c)[0]
print("e_lfanew", hex(e_lfanew), d[e_lfanew:e_lfanew + 4])
print("PE sigs at", [hex(m.start()) for m in re.finditer(rb"PE\x00\x00", d)][:10])
print("MZ at", [hex(m.start()) for m in re.finditer(rb"MZ", d)][:10])
p = pefile.PE(data=d)
oh = p.OPTIONAL_HEADER
print("machine", hex(p.FILE_HEADER.Machine), "magic", hex(oh.Magic), "AEP", hex(oh.AddressOfEntryPoint), "base", hex(oh.ImageBase), "subsys", oh.Subsystem)
print("NumberOfSections", p.FILE_HEADER.NumberOfSections, "TimeDateStamp", p.FILE_HEADER.TimeDateStamp, "Characteristics", hex(p.FILE_HEADER.Characteristics))
for s in p.sections:
    print(" ", s.Name, hex(s.VirtualAddress), hex(s.Misc_VirtualSize), hex(s.PointerToRawData), hex(s.SizeOfRawData), hex(s.Characteristics))
# entry in which section; file offset
try:
    print("entry file offset", hex(p.get_offset_from_rva(oh.AddressOfEntryPoint)))
except Exception as ex:
    print("off err", ex)
print("overlay", p.get_overlay_data_start_offset(), len(d))
ov = p.get_overlay()
if ov: print("overlay head", ov[:200])
# strings mentioning entry / report
for m in re.finditer(rb"[ -~]{6,}", d):
    s = m.group()
    if re.search(rb"(?i)entry|report|telemetry|arch|machine|huntress|0x[0-9a-f]{4,}", s):
        print(hex(m.start()), s[:200])
