"""JNI native-method evaluation for dalvik.py (Day-23 mobile mastery, Day-15 'jni_secret' flavor): `Release.token()` passes the
value through `NativeLibrarySecrets.nativeShare(long)`, a `native` method whose body lives in lib/<abi>/libarena.so
(x86_64 only in the variants seen: 88 bytes of mov/movabs/add/xor/rol/shr/imul/ret).
We locate the mangled export `Java_<class>_<method>` in the ELF symbol tables and run it inside a Unicorn CPU sandbox: only
the ELF PT_LOAD segments (at a fixed bias), a scratch stack, a zero page standing in for JNIEnv*/jclass and a return sentinel
are mapped - no OS, no loader, no syscalls (an interrupt / syscall / unmapped access raises). This is interpretation of the
artifact's arithmetic in an emulator, not execution on the host.
usage: native.py <apk|lib.so> <Lclass;> <method> <jlong-arg>"""
import io, sys, zipfile
from elftools.elf.elffile import ELFFile

ABI_PREF = ["x86_64", "arm64-v8a", "x86", "armeabi-v7a"]
BIAS = 0x10000000
STACK, STACK_SZ = 0x7FF00000, 0x100000
ENV = 0x20000000
SENTINEL = 0x30000000
MASK64 = 0xFFFFFFFFFFFFFFFF


def mangle(cname, mname):
    """JNI short name: Java_<pkg_Class>_<method> with the standard _1 _2 _3 _0xxxx escapes."""
    cls = cname[1:-1] if cname.startswith("L") and cname.endswith(";") else cname

    def esc(s):
        out = []
        for ch in s:
            if ch == "/": out.append("_")
            elif ch == "_": out.append("_1")
            elif ch == ";": out.append("_2")
            elif ch == "[": out.append("_3")
            elif ch.isalnum() and ord(ch) < 128: out.append(ch)
            else: out.append("_0%04x" % ord(ch))
        return "".join(out)
    return "Java_" + esc(cls) + "_" + esc(mname)


def find_export(libs, sym):
    """(abi, elf bytes, st_value, st_size, e_machine) of `sym` (or an overloaded `sym__sig`), preferring emulable ABIs."""
    cands = []
    for path, b in libs.items():
        try:
            e = ELFFile(io.BytesIO(b))
        except Exception:
            continue
        abi = path.split("/")[1] if path.startswith("lib/") and path.count("/") >= 2 else "?"
        for sn in (".dynsym", ".symtab"):
            s = e.get_section_by_name(sn)
            if not s:
                continue
            for symb in s.iter_symbols():
                if symb.name == sym or symb.name.startswith(sym + "__"):
                    cands.append((ABI_PREF.index(abi) if abi in ABI_PREF else 9, abi, b, symb["st_value"], symb["st_size"], e["e_machine"]))
    if not cands:
        return None
    cands.sort(key=lambda t: t[0])
    return cands[0][1:]


def jni_call(libs, cname, mname, shorty, params, args):
    sym = mangle(cname, mname)
    hit = find_export(libs, sym)
    if hit is None:
        raise RuntimeError("native %s not found in %s" % (sym, sorted(libs)))
    abi, b, addr, size, machine = hit
    r = emulate(b, machine, addr, params, args)
    rt = shorty[0]
    if rt == "J":
        r &= MASK64
        return r - (1 << 64) if r & (1 << 63) else r
    if rt in "IBSCZ":
        r &= 0xFFFFFFFF
        return r - (1 << 32) if r & (1 << 31) else r
    if rt == "V":
        return None
    raise RuntimeError("native return type %s not modelled" % rt)


def _map_elf(mu, b):
    e = ELFFile(io.BytesIO(b))
    lo, hi = None, 0
    segs = []
    for seg in e.iter_segments():
        if seg["p_type"] != "PT_LOAD":
            continue
        va, msz = seg["p_vaddr"], seg["p_memsz"]
        segs.append((va, seg.data()))
        lo = va if lo is None else min(lo, va)
        hi = max(hi, va + msz)
    if lo is None:
        raise RuntimeError("no PT_LOAD segments")
    start = (BIAS + lo) & ~0xFFF
    end = (BIAS + hi + 0xFFF) & ~0xFFF
    mu.mem_map(start, end - start)
    for va, data in segs:
        mu.mem_write(BIAS + va, data)


def emulate(b, machine, addr, params, args, max_insns=20_000_000):
    import unicorn
    from unicorn import Uc, UC_HOOK_INTR
    ints = [int(a) & MASK64 for a in args]
    if machine == "EM_X86_64":
        from unicorn import UC_ARCH_X86, UC_MODE_64, UC_HOOK_INSN
        from unicorn.x86_const import (UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX, UC_X86_REG_R8,
                                       UC_X86_REG_R9, UC_X86_REG_RSP, UC_X86_REG_RAX, UC_X86_INS_SYSCALL)
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        _map_elf(mu, b)
        mu.mem_map(STACK, STACK_SZ); mu.mem_map(ENV, 0x10000); mu.mem_map(SENTINEL, 0x1000)
        rsp = STACK + STACK_SZ - 0x1000
        mu.mem_write(rsp, SENTINEL.to_bytes(8, "little"))  # return address
        mu.reg_write(UC_X86_REG_RSP, rsp)
        mu.reg_write(UC_X86_REG_RDI, ENV)            # JNIEnv*
        mu.reg_write(UC_X86_REG_RSI, ENV + 0x8000)   # jclass / jobject
        for reg, v in zip((UC_X86_REG_RDX, UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9), ints):
            mu.reg_write(reg, v)
        if len(ints) > 4:
            for i, v in enumerate(ints[4:]):
                mu.mem_write(rsp + 8 + 8 * i, v.to_bytes(8, "little"))

        def on_syscall(uc, user):
            raise RuntimeError("native code attempted a syscall")
        mu.hook_add(UC_HOOK_INSN, on_syscall, None, 1, 0, UC_X86_INS_SYSCALL)
        mu.hook_add(UC_HOOK_INTR, lambda uc, intno, user: (_ for _ in ()).throw(RuntimeError("interrupt %d" % intno)))
        mu.emu_start(BIAS + addr, SENTINEL, timeout=10_000_000, count=max_insns)
        return mu.reg_read(UC_X86_REG_RAX)
    if machine == "EM_AARCH64":
        from unicorn import UC_ARCH_ARM64, UC_MODE_ARM
        from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_SP, UC_ARM64_REG_X30
        mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        _map_elf(mu, b)
        mu.mem_map(STACK, STACK_SZ); mu.mem_map(ENV, 0x10000); mu.mem_map(SENTINEL, 0x1000)
        mu.reg_write(UC_ARM64_REG_SP, STACK + STACK_SZ - 0x1000)
        mu.reg_write(UC_ARM64_REG_X30, SENTINEL)
        mu.reg_write(UC_ARM64_REG_X0, ENV)
        mu.reg_write(UC_ARM64_REG_X0 + 1, ENV + 0x8000)
        for i, v in enumerate(ints[:6]):
            mu.reg_write(UC_ARM64_REG_X0 + 2 + i, v)
        mu.hook_add(UC_HOOK_INTR, lambda uc, intno, user: (_ for _ in ()).throw(RuntimeError("interrupt %d" % intno)))
        mu.emu_start(BIAS + addr, SENTINEL, timeout=10_000_000, count=max_insns)
        return mu.reg_read(UC_ARM64_REG_X0)
    raise RuntimeError("native ABI %s not supported" % machine)


def libs_from_apk(b):
    z = zipfile.ZipFile(io.BytesIO(b))
    return {n: z.read(n) for n in z.namelist() if n.startswith("lib/") and n.endswith(".so")}


if __name__ == "__main__":
    data = open(sys.argv[1], "rb").read()
    libs = libs_from_apk(data) if data[:2] == b"PK" else {"lib/x86_64/" + sys.argv[1].split("/")[-1]: data}
    print("symbol", mangle(sys.argv[2], sys.argv[3]))
    v = jni_call(libs, sys.argv[2], sys.argv[3], "JJ", ["J"], [int(sys.argv[4], 0)])
    print("result", v, hex(v & MASK64))
