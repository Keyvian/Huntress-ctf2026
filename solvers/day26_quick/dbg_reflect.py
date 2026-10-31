"""debug helper: trace the java.lang.Class / reflect library calls made by Util.routeMazee3 of a Day-19-theme APK and dump
its bytecode. usage: dbg_reflect.py <apk> [Class] [method]"""
import sys, os, zipfile, io
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dalvik

data = open(sys.argv[1], "rb").read()
dexb = zipfile.ZipFile(io.BytesIO(data)).read("classes.dex") if data[:2] == b"PK" else data
dex = dalvik.Dex(dexb)
vm = dalvik.VM(dex)
orig_lib = vm.lib_call


def lib(cname, mname, shorty, args):
    r = orig_lib(cname, mname, shorty, args)
    if cname.startswith("Ljava/lang/Class") or cname.startswith("Ljava/lang/reflect") or mname in ("valueOf", "longValue"):
        print("LIB", cname, mname, shorty, [repr(a)[:60] for a in args], "->", repr(r)[:80])
    return r


vm.lib_call = lib
cls = sys.argv[2] if len(sys.argv) > 2 else "Util"
meth = sys.argv[3] if len(sys.argv) > 3 else "routeMazee3"
cname = dex.find_class("/" + cls + ";")
key = [k for k in dex.classes[cname]["methods"] if isinstance(k, tuple) and k[0] == meth][0]
midx = next(i for i, (mc, mp, mn) in enumerate(dex.methods) if mc == cname and mn == meth and mp[0] == key[1])
print("shorty", key[1], "proto", dex.methods[midx][1])
off = dex.classes[cname]["methods"][key]
regs_n, ins_n, insns = dex.code(off)
print("regs", regs_n, "ins", ins_n, "len", len(insns))
print(insns[:160].hex())
r = vm.invoke(midx, [5264502812172079634])
print("result %016x" % (r & ((1 << 64) - 1)))
