"""Day-31 mobile 'Mobile Arena Gauntlet' = mob30 + a dex class-loader model for dalvik.VM. The mastery campaign replays every released
theme; the Day-20 'Loaded Later' theme (first time in a mastery rotation) does
  new InMemoryDexClassLoader(ByteBuffer.wrap(Assets.read("payload.dex")), Util.class.getClassLoader())
      .loadClass(<name from LoadedLater.moduleContract()>).getDeclaredMethod("share", Long.TYPE).invoke(null, Long.valueOf(j))
A loader owns a child VM over the secondary dex bytes; a class it loads is the tuple ("__loaded__", child_vm, descriptor). Nothing is
executed natively: the secondary dex runs in the same pure-Python interpreter.
usage: mob31.py <challenge> [--submit] [--retry|--practice] [--save dir] | mob31.py --local file...
       mob31.py --layered <data> <key>"""
import sys, os, runpy
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dalvik
import mob30  # noqa: F401  (installs the v1 codecs into mob19.dec)

LOADERS = ("Ldalvik/system/InMemoryDexClassLoader;", "Ldalvik/system/BaseDexClassLoader;", "Ldalvik/system/DexClassLoader;",
           "Ljava/lang/ClassLoader;", "Ljava/security/SecureClassLoader;")
_lib_call = dalvik.VM.lib_call
_reflect_invoke = dalvik.VM.reflect_invoke


def _dex_bytes(v, vm):
    if isinstance(v, dict) and "buf" in v:
        return bytes(v["buf"])
    if isinstance(v, list):
        return vm._ubytes(v)
    return bytes(v)


def lib_call(self, cname, mname, shorty, args):
    if cname == "Ljava/lang/Class;":
        if mname == "getClassLoader":
            return {"__class__": "Ljava/lang/ClassLoader;", "vm": None}
        if args and isinstance(args[0], tuple) and args[0][0] == "__loaded__":
            child, desc = args[0][1], args[0][2]
            if mname in ("getDeclaredMethod", "getMethod"):
                return ("__method__", args[0], args[1], list(args[2] or []) if len(args) > 2 else [])
            if mname == "getName":
                return desc[1:-1].replace("/", ".")
            if mname == "getSimpleName":
                return desc[1:-1].split("/")[-1]
    if cname in LOADERS:
        ld = args[0]
        if mname == "<init>":
            if cname == "Ldalvik/system/InMemoryDexClassLoader;":
                ld["vm"] = dalvik.VM(dalvik.Dex(_dex_bytes(args[1], self)), max_steps=self.max_steps, libs=self.libs,
                                     splits=[(p, b) for p, b in self.splits.items()])
                return None
        if mname == "loadClass":
            d = "L" + str(args[1]).replace(".", "/") + ";"
            if ld.get("vm") is not None and d in ld["vm"].dex.classes:
                return ("__loaded__", ld["vm"], d)
            return self._class_desc(args[1])
    return _lib_call(self, cname, mname, shorty, args)


def reflect_invoke(self, m, receiver, arglist):
    if isinstance(m[1], tuple) and m[1][0] == "__loaded__":
        child, desc = m[1][1], m[1][2]
        self.trace.append((desc, m[2] + "[loaded]"))
        r = child.reflect_invoke(("__method__", desc, m[2], m[3]), receiver, arglist)
        self.steps += child.steps
        child.steps = 0
        return r
    return _reflect_invoke(self, m, receiver, arglist)


dalvik.VM.lib_call = lib_call
dalvik.VM.reflect_invoke = reflect_invoke

if __name__ == "__main__":
    if len(sys.argv) > 3 and sys.argv[1] == "--layered":
        print(mob30.decode_layered(sys.argv[2], {"key": sys.argv[3]}, verbose=True)); sys.exit(0)
    sys.argv[0] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mob26.py")
    runpy.run_path(sys.argv[0], run_name="__main__")
