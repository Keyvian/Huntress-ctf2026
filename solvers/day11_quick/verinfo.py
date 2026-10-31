"""Dump PE VS_VERSIONINFO (StringFileInfo + FixedFileInfo + VarFileInfo) for every PE in a (nested, maybe AES) zip.
usage: verinfo.py <zipfile>"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pefile
from m11 import unzip_all, version_strings

for p, b in unzip_all(open(sys.argv[1], "rb").read()):
    if b[:2] != b"MZ":
        print(p, len(b), b[:8]); continue
    pe = pefile.PE(data=b, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
    print("==", p, len(b), "machine 0x%x" % pe.FILE_HEADER.Machine)
    for k, v in version_strings(b).items():
        print("   %-24s %r" % (k, v))
    for fi in getattr(pe, "VS_FIXEDFILEINFO", []) or []:
        print("   FIXED FileVersion %d.%d.%d.%d ProductVersion %d.%d.%d.%d" % (
            fi.FileVersionMS >> 16, fi.FileVersionMS & 0xffff, fi.FileVersionLS >> 16, fi.FileVersionLS & 0xffff,
            fi.ProductVersionMS >> 16, fi.ProductVersionMS & 0xffff, fi.ProductVersionLS >> 16, fi.ProductVersionLS & 0xffff))
    for fi in getattr(pe, "FileInfo", []) or []:
        for e in fi:
            if hasattr(e, "Var"):
                for v in e.Var:
                    print("   VAR", v.entry)
            if hasattr(e, "StringTable"):
                for t in e.StringTable:
                    print("   TABLE lang", t.LangID)
