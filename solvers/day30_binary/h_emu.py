"""Unicorn harness for sha1-hulud.exe: the sample is NEVER executed natively. A minimal fake Windows layer runs main().
All Win32/NT APIs land on ntdll-shaped stubs (mov r10,rcx / mov eax,ssn / syscall / ret); the syscall hook dispatches by
SSN, so hash-resolved APIs, IAT calls and the sample's direct syscalls share one table. Exceptions are delivered to the
registered VEH handlers through a real CONTEXT/EXCEPTION_RECORD, including TF single-step and execute faults.
usage: h_emu.py <flag guess> [--log] [--max N] [--dump rva:len ...] [--bp rva ...]"""
import os, struct, sys, time, json
import pefile
from unicorn import *
from unicorn.x86_const import *

P = "~/d30/hulud/x/sha1-hulud.exe"
SYS = "/mnt/c/Windows/System32/"
BASE = 0x140000000
STUB = 0x70000000
SENT = 0x71000000
STACK = 0x10000000
STACK_SZ = 0x800000
TEB = 0x7ff00000
PEB = 0x7ff10000
TLS = 0x7ff20000
HEAP = 0x20000000
HEAP_SZ = 0x4000000
KUSER = 0x7ffe0000
HEAP_HANDLE = 0x20000000
M64 = (1 << 64) - 1
TRACE = "--trace" in sys.argv
LOG2B = "--log2b" in sys.argv
RDTSC_SITES = [int(x, 16) for x in os.environ.get("RDTSC_SITES", "").split(",") if x]
if not RDTSC_SITES and os.path.exists("~/d30/hulud/rdtsc_sites.txt"):
    RDTSC_SITES = [int(x, 16) for x in open("~/d30/hulud/rdtsc_sites.txt").read().split()]
GPR = [("rax", 0x78), ("rcx", 0x80), ("rdx", 0x88), ("rbx", 0x90), ("rsp", 0x98), ("rbp", 0xa0), ("rsi", 0xa8), ("rdi", 0xb0),
       ("r8", 0xb8), ("r9", 0xc0), ("r10", 0xc8), ("r11", 0xd0), ("r12", 0xd8), ("r13", 0xe0), ("r14", 0xe8), ("r15", 0xf0),
       ("rip", 0xf8)]
RID = {n: getattr(sys.modules["unicorn.x86_const"], "UC_X86_REG_" + n.upper()) for n, _ in GPR}
RID["eflags"] = UC_X86_REG_EFLAGS


def rol32(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xffffffff


def h_str(s):
    h = 0x1e4bd7ac
    for c in s:
        if c == 0:
            break
        h ^= c
        x = rol32((h * 0x5e565a7b) & 0xffffffff, 15)
        h = (x >> 16) ^ x
    return h


def h_mod(s):
    h = 0x1e4bd7ac
    for c in s.lower().encode():
        h ^= c
        x = rol32((h * 0x5e565a7b) & 0xffffffff, 15)
        h = (x >> 16) ^ x
    return h


def lznt1(src):
    out, p = bytearray(), 0
    while p + 2 <= len(src):
        hdr = struct.unpack("<H", src[p:p + 2])[0]
        if hdr == 0:
            break
        p += 2
        sz = (hdr & 0xfff) + 1
        chunk = src[p:p + sz]
        p += sz
        if not hdr & 0x8000:
            out += chunk
            continue
        start, i = len(out), 0
        while i < len(chunk):
            flags = chunk[i]; i += 1
            for b in range(8):
                if i >= len(chunk):
                    break
                if flags >> b & 1:
                    tok = struct.unpack("<H", chunk[i:i + 2])[0]; i += 2
                    pos = len(out) - start - 1
                    bits = 4
                    while pos >= 1 << bits:
                        bits += 1
                    lmask = (1 << (16 - bits)) - 1
                    length = (tok & lmask) + 3
                    off = (tok >> (16 - bits)) + 1
                    for _ in range(length):
                        out.append(out[-off])
                else:
                    out.append(chunk[i]); i += 1
    return bytes(out)


def build_hashes():
    cache = "~/d30/hulud/exports.json"
    if os.path.exists(cache):
        return {int(k): v for k, v in json.load(open(cache)).items()}
    out = {}
    for dll in ("ntdll.dll", "kernel32.dll", "KernelBase.dll", "advapi32.dll", "user32.dll", "psapi.dll", "ws2_32.dll"):
        pe = pefile.PE(SYS + dll, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if e.name:
                out.setdefault(h_str(e.name), e.name.decode())
    json.dump(out, open(cache, "w"))
    return out


class Emu:
    def __init__(self, flag, log=False, maxinsn=0):
        self.flag = flag
        self.log = log
        self.maxinsn = maxinsn
        self.pe = pefile.PE(P)
        self.img = bytes(self.pe.get_memory_mapped_image())
        self.names = build_hashes()
        self.stubs = {}
        self.ssn = {}
        self.pending = None
        self.state = "run"
        self.veh = []
        self.heap = HEAP + 0x1000
        self.sizes = {}
        self.tsc = 0x100000
        self.tick = 0x1000000
        self.vt = 0x100000
        self.prot = {}
        self.output = b""
        self.stdin = flag.encode() + b"\r\n"
        self.calls = []
        self.stop = False
        self.tf_pending = False
        self.icount = 0
        self.bp = {}
        self.handles = 0x1000
        self.mu = Uc(UC_ARCH_X86, UC_MODE_64)
        self.setup()

    # ---- setup -------------------------------------------------------------------------------------------------
    def setup(self):
        mu = self.mu
        size = (len(self.img) + 0xfff) & ~0xfff
        mu.mem_map(BASE, 0xa2000, UC_PROT_READ)
        mu.mem_write(BASE, self.img)
        for s in self.pe.sections:
            ch = s.Characteristics
            p = UC_PROT_READ
            if ch & 0x80000000: p |= UC_PROT_WRITE
            if ch & 0x20000000: p |= UC_PROT_EXEC
            a = BASE + s.VirtualAddress
            sz = (s.Misc_VirtualSize + 0xfff) & ~0xfff
            mu.mem_protect(a, sz, p)
        # TLS callback 0x637df runs before main on a real loader: [0x98008] = mix(hModule ^ 0x828be76a59740b3e)
        x = (BASE ^ 0x828be76a59740b3e) * 0x406aa9c82dbf9701 & M64
        x ^= x >> 29
        x = x * 0xeb591050d1f713a9 & M64
        x ^= x >> 32
        mu.mem_write(BASE + 0x98008, struct.pack("<Q", x))
        mu.mem_map(STACK, STACK_SZ, UC_PROT_READ | UC_PROT_WRITE)
        mu.mem_map(HEAP, HEAP_SZ, UC_PROT_READ | UC_PROT_WRITE)
        mu.mem_map(TEB, 0x40000, UC_PROT_READ | UC_PROT_WRITE)
        mu.mem_map(KUSER, 0x1000, UC_PROT_READ)
        mu.mem_map(STUB, 0x100000, UC_PROT_READ | UC_PROT_EXEC)
        mu.mem_map(SENT, 0x1000, UC_PROT_READ | UC_PROT_EXEC)
        mu.mem_write(SENT, b"\xc3" * 0x1000)
        # KUSER_SHARED_DATA: InterruptTime @8, SystemTime @0x14, TickCount @0x320, NumberOfPhysicalPages etc
        k = bytearray(0x1000)
        struct.pack_into("<IIIIII", k, 8, 0x100000, 0, 0, 0x9abcdef0, 0x1dc0000, 0x1dc0000)
        struct.pack_into("<I", k, 0x26c, 10)      # NtMajorVersion
        struct.pack_into("<I", k, 0x270, 0)
        struct.pack_into("<I", k, 0x2d4, 0)       # KdDebuggerEnabled area
        struct.pack_into("<Q", k, 0x320, 0x100000)
        struct.pack_into("<I", k, 0x260, 19045)   # NtBuildNumber
        struct.pack_into("<I", k, 0x2e8, 0x400000)  # NumberOfPhysicalPages (16 GiB)
        struct.pack_into("<I", k, 0x3c0, 8)       # ActiveProcessorCount
        k[0x3c4] = 1                              # ActiveGroupCount
        struct.pack_into("<Q", k, 0x3d8, 3)       # XState.EnabledFeatures
        for f in (12, 13, 17):                    # PF_NX_ENABLED, PF_SSE3, PF_XSAVE_ENABLED
            k[0x274 + f] = 1
        mu.mem_write(KUSER, bytes(k))
        # TEB / PEB
        t = bytearray(0x2000)
        struct.pack_into("<Q", t, 0x08, STACK + STACK_SZ)
        struct.pack_into("<Q", t, 0x10, STACK)
        struct.pack_into("<Q", t, 0x30, TEB)
        struct.pack_into("<Q", t, 0x40, 0x1234)   # pid
        struct.pack_into("<Q", t, 0x48, 0x5678)   # tid
        struct.pack_into("<Q", t, 0x58, TLS)
        struct.pack_into("<Q", t, 0x60, PEB)
        mu.mem_write(TEB, bytes(t))
        p = bytearray(0x1000)
        struct.pack_into("<Q", p, 0x10, BASE)
        struct.pack_into("<Q", p, 0x18, PEB + 0x800)
        struct.pack_into("<Q", p, 0x30, HEAP_HANDLE)
        struct.pack_into("<I", p, 0xb8, 8)        # NumberOfProcessors
        struct.pack_into("<H", p, 0x118, 10)
        struct.pack_into("<I", p, 0x120, 19045)
        l = PEB + 0x800 + 0x20
        struct.pack_into("<QQ", p, 0x820, l, l)   # empty InMemoryOrderModuleList
        mu.mem_write(PEB, bytes(p))
        mu.mem_write(TLS, struct.pack("<Q", TLS + 0x100))
        mu.msr_write(0xC0000101, TEB)             # IA32_GS_BASE
        # IAT -> stubs
        for e in self.pe.DIRECTORY_ENTRY_IMPORT:
            for i in e.imports:
                nm = i.name.decode() if i.name else str(i.ordinal)
                mu.mem_write(i.address, struct.pack("<Q", self.stub(nm)))
        mu.hook_add(UC_HOOK_INSN, self.on_syscall, None, 1, 0, UC_X86_INS_SYSCALL)
        mu.hook_add(UC_HOOK_INTR, self.on_intr)
        mu.hook_add(UC_HOOK_INSN_INVALID, self.on_invalid)
        mu.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED | UC_HOOK_MEM_FETCH_PROT, self.on_fetch)
        mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_READ_PROT | UC_HOOK_MEM_WRITE_PROT, self.on_data_fault)
        mu.hook_add(UC_HOOK_CODE, self.on_sentinel, None, SENT, SENT + 0xfff)
        mu.hook_add(UC_HOOK_CODE, self.on_resolver, None, BASE + 0x64480, BASE + 0x64480)
        if TRACE:
            mu.hook_add(UC_HOOK_CODE, self.on_code, None, BASE + 0x1000, BASE + 0x7f000)
        for a in RDTSC_SITES:
            mu.hook_add(UC_HOOK_CODE, self.on_rdtsc_site, None, BASE + a, BASE + a)

    def stub(self, name):
        if name in self.stubs:
            return self.stubs[name]
        n = len(self.stubs)
        a = STUB + n * 32
        self.mu.mem_write(a, b"\x4c\x8b\xd1\xb8" + struct.pack("<I", 0x1000 + n) + b"\x0f\x05\xc3" + b"\x90" * 21)
        self.stubs[name] = a
        self.ssn[0x1000 + n] = name
        return a

    # ---- register helpers --------------------------------------------------------------------------------------
    def r(self, n):
        return self.mu.reg_read(RID[n])

    def w(self, n, v):
        self.mu.reg_write(RID[n], v)

    def q(self, a):
        return struct.unpack("<Q", self.mu.mem_read(a, 8))[0]

    def d(self, a):
        return struct.unpack("<I", self.mu.mem_read(a, 4))[0]

    def wq(self, a, v):
        self.mu.mem_write(a, struct.pack("<Q", v & M64))

    def wd(self, a, v):
        self.mu.mem_write(a, struct.pack("<I", v & 0xffffffff))

    # ---- hooks -------------------------------------------------------------------------------------------------
    def on_resolver(self, mu, addr, size, ud):
        # 0x64480(module hash, function hash): answer with a stub, return to the caller
        fn = self.r("rdx") & 0xffffffff
        name = self.names.get(fn, "hash_%08x" % fn)
        if self.log:
            print("resolve", name, flush=True)
        self.w("rax", self.stub(name))
        ret = self.q(self.r("rsp"))
        self.w("rsp", self.r("rsp") + 8)
        self.w("rip", ret)

    def on_code(self, mu, addr, size, ud):
        self.icount += 1
        if self.icount & 0xfffff == 0:
            print("  .. icount %dM pc=%x" % (self.icount >> 20, addr - BASE), flush=True)
            if self.maxinsn and self.icount >= self.maxinsn:
                self.fatal("maxinsn")
        if addr in self.bp:
            self.bp[addr](self)

    def on_sdbg(self, mu, addr, size, ud):
        self.bp[addr](self)

    def add_bp(self, rva, fn):
        self.bp[BASE + rva] = fn
        self.mu.hook_add(UC_HOOK_CODE, self.on_sdbg, None, BASE + rva, BASE + rva)

    def clk(self, step=2):
        # one virtual clock in 100 ns units: QPC = vt (10 MHz), TSC = 300 * vt (3 GHz), KUSER interrupt time = vt
        self.vt += step
        self.mu.mem_write(KUSER + 8, struct.pack("<III", self.vt & 0xffffffff, self.vt >> 32, self.vt >> 32))
        return self.vt

    def on_rdtsc_site(self, mu, addr, size, ud):
        t = self.clk() * 300
        self.nrdtsc = getattr(self, "nrdtsc", 0) + 1
        mu.reg_write(UC_X86_REG_RAX, t & 0xffffffff)
        mu.reg_write(UC_X86_REG_RDX, t >> 32)
        mu.reg_write(UC_X86_REG_RIP, addr + 2)

    def on_intr(self, mu, intno, ud):
        rip = self.r("rip")
        if intno == 3:
            a = rip - 1 if bytes(mu.mem_read(rip - 1, 1)) == b"\xcc" else rip
            self.raise_exc(0x80000003, a, [])
        elif intno == 1:
            self.raise_exc(0x80000004, rip, [])
        elif intno == 0x2d:
            self.raise_exc(0x80000003, rip, [])
        elif intno == 6:
            self.raise_exc(0xc000001d, rip, [])
        else:
            print("INT", intno, hex(rip)); self.fatal("int")
        mu.emu_stop()

    def on_invalid(self, mu, ud):
        rip = self.r("rip")
        self.raise_exc(0xc000001d, rip, [])
        mu.emu_stop()
        return True

    def on_fetch(self, mu, access, addr, size, value, ud):
        self.raise_exc(0xc0000005, addr, [8, addr])
        mu.emu_stop()
        return False

    def on_data_fault(self, mu, access, addr, size, value, ud):
        rip = self.r("rip")
        wr = access in (UC_MEM_WRITE_UNMAPPED, UC_MEM_WRITE_PROT)
        self.raise_exc(0xc0000005, rip, [1 if wr else 0, addr])
        mu.emu_stop()
        return False

    def on_sentinel(self, mu, addr, size, ud):
        self.state = "main_done" if addr == SENT + 0x100 else "handler_done"
        mu.emu_stop()

    def fatal(self, why):
        print("FATAL", why, "rip=%x" % (self.r("rip") - BASE), "icount", self.icount, flush=True)
        self.stop = True
        self.mu.emu_stop()

    # ---- exceptions --------------------------------------------------------------------------------------------
    def raise_exc(self, code, addr, params):
        self.pending = (code, addr, params)

    def deliver(self):
        code, addr, params = self.pending
        self.pending = None
        self.nexc = getattr(self, "nexc", 0) + 1
        if self.nexc % 500 == 0:
            print("  exc#%d %08x at %x t=%.1f" % (self.nexc, code, addr - BASE, time.time() - self.t0), flush=True)
        if self.log:
            print("EXC %08x at %x params %s veh=%d" % (code, addr - BASE, [hex(x) for x in params], len(self.veh)), flush=True)
        mu = self.mu
        rsp = (self.r("rsp") - 0x1000) & ~0xf
        ctx = rsp + 0x100
        rec = ctx + 0x500
        ptrs = rec + 0x100
        mu.mem_write(ctx, b"\x00" * 0x4d0)
        self.wd(ctx + 0x30, 0x10001f)
        self.wd(ctx + 0x44, self.r("eflags") & ~0x100 if False else self.r("eflags"))
        for n, off in GPR:
            self.wq(ctx + off, self.r(n))
        self.wq(ctx + 0xf8, addr)
        mu.mem_write(rec, b"\x00" * 0x98)
        self.wd(rec, code)
        self.wq(rec + 0x10, addr)
        self.wd(rec + 0x18, len(params))
        for i, p in enumerate(params):
            self.wq(rec + 0x20 + i * 8, p)
        self.wq(ptrs, rec)
        self.wq(ptrs + 8, ctx)
        handled = False
        for h in list(self.veh):
            self.w("rsp", rsp - 8)
            self.wq(rsp - 8, SENT)
            self.w("rcx", ptrs)
            self.w("rip", h)
            self.w("eflags", 0x202)
            self.state = "handler"
            self.tf_pending = False
            mu.emu_start(h, 0)
            if self.state != "handler_done":
                self.fatal("handler did not return, state %s" % self.state)
                return
            if (self.r("rax") & 0xffffffff) == 0xffffffff:
                handled = True
                break
        if not handled:
            self.fatal("unhandled exception %08x at %x" % (code, addr - BASE))
            return
        for n, off in GPR:
            self.w(n, self.q(ctx + off))
        self.w("eflags", self.d(ctx + 0x44))
        self.tf_pending = False

    # ---- API layer ---------------------------------------------------------------------------------------------
    def on_syscall(self, mu, ud):
        n = self.r("rax") & 0xffffffff
        name = self.ssn.get(n, "ssn_%x" % n)
        a1, a2, a3, a4 = self.r("r10"), self.r("rdx"), self.r("r8"), self.r("r9")
        rsp = self.r("rsp")
        f = getattr(self, "api_" + name, None)
        if self.log:
            print("API %-34s %x %x %x %x -> ret %x" % (name, a1, a2, a3, a4, self.q(rsp) - BASE), flush=True)
        self.calls.append(name)
        if f is None:
            if name not in ("x",):
                print("UNIMPLEMENTED API", name, "ret %x" % (self.q(rsp) - BASE), flush=True)
            self.w("rax", 0)
            return
        v = f(a1, a2, a3, a4, rsp)
        self.w("rax", (v or 0) & M64)

    def stk(self, rsp, i):
        return self.q(rsp + 0x28 + (i - 5) * 8)

    def api_GetProcessHeap(self, *a): return HEAP_HANDLE
    def api_GetCurrentThreadId(self, *a): return 0x5678
    def api_GetCurrentProcessId(self, *a): return 0x1234
    def api_GetCurrentThread(self, *a): return M64 - 1
    def api_GetCurrentProcess(self, *a): return M64
    def api_GetLastError(self, *a): return self.d(TEB + 0x68)
    def api_SetLastError(self, a1, *a):
        self.lasterr(a1)
        return 0
    def api_IsDebuggerPresent(self, *a): return 0
    def api_VirtualProtect(self, a1, a2, a3, a4, rsp):
        self.mu.mem_write(a4, struct.pack("<I", self.prot.get(a1, 0x20)))
        self.prot[a1] = a3
        base = a1 & ~0xfff
        end = (a1 + a2 + 0xfff) & ~0xfff
        p = {0x40: 7, 0x20: 5, 0x04: 3, 0x02: 1, 0x01: 0, 0x10: 4}.get(a3, 7)
        self.mu.mem_protect(base, end - base, p)
        return 1

    def api_GetThreadContext(self, a1, a2, a3, a4, rsp):
        self.mu.mem_write(a2 + 0x48, b"\x00" * 0x30)
        return 1

    def api_NtGetContextThread(self, a1, a2, a3, a4, rsp):
        self.mu.mem_write(a2 + 0x48, b"\x00" * 0x30)
        return 0

    def api_HeapAlloc(self, a1, a2, a3, a4, rsp):
        n = (a3 + 0x1f) & ~0xf
        p = self.heap
        self.heap += n
        self.sizes[p] = a3
        if a2 & 8:
            self.mu.mem_write(p, b"\x00" * a3)
        return p

    def api_HeapFree(self, *a): return 1

    def api_HeapReAlloc(self, a1, a2, a3, a4, rsp):
        p = self.api_HeapAlloc(a1, a2 & 8, a4, 0, rsp)
        old = self.sizes.get(a3, 0)
        self.mu.mem_write(p, bytes(self.mu.mem_read(a3, min(old, a4))))
        return p

    def api_HeapSize(self, a1, a2, a3, a4, rsp): return self.sizes.get(a3, 0)

    def api_RtlAddVectoredExceptionHandler(self, a1, a2, a3, a4, rsp):
        if a2 not in self.veh:
            if a1: self.veh.insert(0, a2)
            else: self.veh.append(a2)
        return a2

    api_AddVectoredExceptionHandler = api_RtlAddVectoredExceptionHandler

    def api_RtlRemoveVectoredExceptionHandler(self, a1, *a):
        if a1 in self.veh:
            self.veh.remove(a1)
        return 1

    def api_NtSetInformationThread(self, *a): return 0
    def api_NtQueryInformationThread(self, a1, a2, a3, a4, rsp):
        self.mu.mem_write(a3, b"\x00" * a4)
        return 0

    def api_NtQueryInformationProcess(self, a1, a2, a3, a4, rsp):
        if a2 == 0x1e:
            self.mu.mem_write(a3, b"\x00" * a4)
            return 0xC0000353
        if a2 == 0x1f:
            self.mu.mem_write(a3, struct.pack("<I", 1))
            return 0
        if a2 == 0:
            self.mu.mem_write(a3, struct.pack("<QQQQQQ", 0x103, PEB, 0xff, 8, 0x1234, 0x4567))
            return 0
        self.mu.mem_write(a3, b"\x00" * a4)
        return 0

    def api_NtQuerySystemInformation(self, a1, a2, a3, a4, rsp):
        if a1 == 0x23:
            self.mu.mem_write(a2, b"\x00\x01")
        return 0

    def api_RtlPcToFileHeader(self, a1, a2, a3, a4, rsp):
        self.wq(a2, BASE)
        return BASE

    def api_GetModuleHandleExW(self, a1, a2, a3, a4, rsp):
        self.wq(a3, BASE)
        return 1

    def api_CheckRemoteDebuggerPresent(self, a1, a2, a3, a4, rsp):
        self.wd(a2, 0)
        return 1

    def lasterr(self, v):
        self.wd(TEB + 0x68, v)

    def api_VirtualAlloc(self, a1, a2, a3, a4, rsp):
        if a2 == 0:
            self.lasterr(87)        # ERROR_INVALID_PARAMETER
            return 0
        self.valloc = getattr(self, "valloc", 0x30000000)
        size = (a2 + 0xfff) & ~0xfff
        p = a1 or self.valloc
        if not a1:
            self.valloc += size + 0x10000
        prot = {0x40: 7, 0x20: 5, 0x04: 3, 0x02: 1, 0x01: 0, 0x10: 4}.get(a4, 3)
        try:
            self.mu.mem_map(p, size, prot)
        except UcError:
            pass
        print("VirtualAlloc %x size %x prot %x -> %x ret %x" % (a1, a2, a4, p, self.q(rsp) - BASE), flush=True)
        self.prot[p] = a4
        return p

    def api_VirtualFree(self, a1, a2, a3, a4, rsp):
        print("VirtualFree %x %x %x" % (a1, a2, a3), flush=True)
        if a1 == 0:
            self.lasterr(487)       # ERROR_INVALID_ADDRESS
            return 0
        return 1

    def api_GetSystemDirectoryW(self, a1, a2, a3, a4, rsp):
        s = "C:\\Windows\\system32"
        self.mu.mem_write(a1, s.encode("utf-16le") + b"\x00\x00")
        return len(s)

    def api_IsProcessorFeaturePresent(self, a1, *a):
        print("IsProcessorFeaturePresent", a1, flush=True)
        return 1

    def api_Sleep(self, a1, *a):
        self.clk((a1 & 0xffffffff) * 10000)
        return 0

    def api_RtlGetVersion(self, a1, *a):
        self.mu.mem_write(a1 + 4, struct.pack("<IIII", 10, 0, 19045, 2))
        return 0

    def api_NtQueryVirtualMemory(self, a1, a2, a3, a4, rsp):
        print("NtQueryVirtualMemory %x class %x buf %x" % (a2, a3, a4), flush=True)
        if a3 != 0:
            return 0xC0000003
        mbi = struct.pack("<QQIIQIIII", a2 & ~0xfff, BASE, 0x80, 0, 0x7e000, 0x1000, 0x20, 0x1000000, 0)
        self.mu.mem_write(a4, mbi)
        rl = self.stk(rsp, 6)
        if rl:
            self.wq(rl, 0x30)
        return 0

    def api_RtlDecompressBuffer(self, a1, a2, a3, a4, rsp):
        src_len, final = self.stk(rsp, 5), self.stk(rsp, 6)
        src = bytes(self.mu.mem_read(a4, src_len & 0xffffffff))
        print("RtlDecompressBuffer fmt=%x dst=%x dstlen=%x src=%x srclen=%x head=%s" % (a1, a2, a3, a4, src_len, src[:32].hex()), flush=True)
        open("~/d30/hulud/compressed.bin", "wb").write(src)
        out = lznt1(src)
        self.mu.mem_write(a2, out[:a3])
        self.wd(final, min(len(out), a3))
        open("~/d30/hulud/decompressed.bin", "wb").write(out)
        print("  decompressed", len(out), out[:32].hex(), flush=True)
        return 0

    def api_GetEnabledXStateFeatures(self, *a): return 7

    def api_GetSystemFirmwareTable(self, a1, a2, a3, a4, rsp):
        n = 0x400                                 # RawSMBIOSData: 8-byte header (Length at +4), then the tables
        if a3 and a4 >= n:
            self.mu.mem_write(a3, b"\x00\x03\x03\x00" + struct.pack("<I", n - 8) + b"\x7f\x04\x00\x00" + b"\x00" * (n - 12))
        return n

    def api_EnumSystemFirmwareTables(self, a1, a2, a3, a4, rsp):
        ids = [0x50434146, 0x43495041, 0x54445344, 0x54455048, 0x4746434d, 0x54495741]  # FACP APIC DSDT HPET MCFG WAET
        d = b"".join(struct.pack("<I", x) for x in ids)
        if a2 and a3 >= len(d):
            self.mu.mem_write(a2, d)
        return len(d)

    def api_GetSystemInfo(self, a1, *a):
        si = struct.pack("<HHIQQQIIIHH", 9, 0, 0x1000, 0x10000, 0x7ffeffff, 0xff, 8, 8664, 0x10000, 6, 0xa507)
        self.mu.mem_write(a1, si)
        return 0

    def api_GlobalMemoryStatusEx(self, a1, *a):
        self.mu.mem_write(a1 + 4, struct.pack("<IQQQQQQQ", 30, 16 << 30, 10 << 30, 32 << 30, 24 << 30, 1 << 47, (1 << 47) - (1 << 30), 0))
        return 1

    def api_CreateFileW(self, a1, a2, a3, a4, rsp):
        s = bytes(self.mu.mem_read(a1, 520)).decode("utf-16le", "replace").split("\x00")[0]
        print("CreateFileW", repr(s), "access %x" % a2, flush=True)
        return M64

    def api_CloseHandle(self, a1, *a):
        return 0 if a1 == 0xdeadbeef else 1

    # registry: a plausible workstation (the sample counts Services / SOFTWARE subkeys as a sandbox check)
    def cstr(self, a, n=260):
        return bytes(self.mu.mem_read(a, n)).split(b"\x00")[0].decode("latin-1")

    def api_RegOpenKeyExA(self, a1, a2, a3, a4, rsp):
        p = self.cstr(a2)
        self.handles += 4
        self.regkeys = getattr(self, "regkeys", {})
        self.regkeys[self.handles] = (p, 800 if "Services" in p else 64)
        self.wq(self.stk(rsp, 5), self.handles)
        print("RegOpenKeyExA", hex(a1), p, flush=True)
        return 0

    def api_RegCloseKey(self, *a): return 0

    def api_RegEnumKeyExA(self, a1, a2, a3, a4, rsp):
        p, n = self.regkeys.get(a1, ("?", 0))
        if a2 >= n:
            return 259
        nm = ("Svc%04d" % a2).encode()
        self.mu.mem_write(a3, nm + b"\x00")
        self.wd(a4, len(nm))
        return 0

    def api_RegQueryInfoKeyA(self, a1, a2, a3, a4, rsp):
        p, n = self.regkeys.get(a1, ("?", 0))
        sub = self.stk(rsp, 5)
        if sub:
            self.wd(sub, n)
        print("RegQueryInfoKeyA", p, n, flush=True)
        return 0

    def api_GetStdHandle(self, a1, *a): return 0x100 + (a1 & 0xff)
    def api_GetConsoleMode(self, *a): return 0
    def api_GetFileType(self, *a): return 2
    def api_GetTickCount64(self, *a):
        return self.clk() // 10000
    def api_GetTickCount(self, *a):
        return (self.clk() // 10000) & 0xffffffff
    def api_QueryPerformanceCounter(self, a1, *a):
        self.wq(a1, self.clk())
        return 1

    def api_QueryPerformanceFrequency(self, a1, *a):
        self.wq(a1, 10000000); return 1

    def api_NtQueryPerformanceCounter(self, a1, a2, *a):
        self.wq(a1, self.clk())
        if a2: self.wq(a2, 10000000)
        return 0

    def api_GetSystemTimeAsFileTime(self, a1, *a):
        self.wq(a1, 0x1dc000000000000 + self.clk()); return 0

    def api_NtWriteFile(self, a1, a2, a3, a4, rsp):
        iosb, buf, ln = self.stk(rsp, 5), self.stk(rsp, 6), self.stk(rsp, 7)
        d = bytes(self.mu.mem_read(buf, ln & 0xffffffff))
        self.output += d
        print("STDOUT", d, flush=True)
        self.wq(iosb, 0)
        self.wq(iosb + 8, len(d))
        return 0

    def api_NtReadFile(self, a1, a2, a3, a4, rsp):
        iosb, buf, ln = self.stk(rsp, 5), self.stk(rsp, 6), self.stk(rsp, 7)
        d = self.stdin[:ln]
        self.stdin = self.stdin[len(d):]
        self.mu.mem_write(buf, d)
        self.wq(iosb, 0)
        self.wq(iosb + 8, len(d))
        print("STDIN read", d, "at icount", self.icount, flush=True)
        return 0

    def api_ExitProcess(self, *a):
        self.fatal("ExitProcess")

    def api_NtTerminateProcess(self, *a):
        self.fatal("NtTerminateProcess")

    def api_TerminateProcess(self, *a):
        self.fatal("TerminateProcess")

    # ---- snapshot ----------------------------------------------------------------------------------------------
    REGIONS = [(BASE, 0xa2000), (STACK, STACK_SZ), (HEAP, HEAP_SZ), (TEB, 0x40000), (STUB, 0x100000)]

    def snapshot(self, path):
        import pickle
        regs = {n: self.r(n) for n, _ in GPR}
        regs["eflags"] = self.r("eflags")
        xmm = [self.mu.reg_read(UC_X86_REG_XMM0 + i) for i in range(16)]
        mem = {b: bytes(self.mu.mem_read(b, n)) if b != HEAP else bytes(self.mu.mem_read(b, self.heap - HEAP + 0x1000))
               for b, n in self.REGIONS}
        st = dict(regs=regs, xmm=xmm, mem=mem, heap=self.heap, sizes=self.sizes, veh=self.veh, stubs=self.stubs, ssn=self.ssn,
                  stdin=self.stdin, tsc=self.tsc, tick=self.tick, output=self.output, mapped=list(self.mu.mem_regions()))
        pickle.dump(st, open(path, "wb"))
        print("SNAPSHOT saved", path, "at rip %x" % (regs["rip"] - BASE), flush=True)

    def restore(self, path):
        import pickle
        st = pickle.load(open(path, "rb"))
        self.mu.mem_protect(BASE, 0xa2000, 7)
        for b, d in st["mem"].items():
            self.mu.mem_write(b, d)
        for a, e, p in st["mapped"]:
            if BASE <= a < BASE + 0xa2000:
                self.mu.mem_protect(a, e - a + 1, p)
        self.heap, self.sizes, self.veh, self.stubs, self.ssn = st["heap"], st["sizes"], st["veh"], st["stubs"], st["ssn"]
        self.stdin, self.tsc, self.tick, self.output = st["stdin"], st["tsc"], st["tick"], st["output"]
        for i, v in enumerate(st["xmm"]):
            self.mu.reg_write(UC_X86_REG_XMM0 + i, v)
        for n, v in st["regs"].items():
            if n != "rip":
                self.w(n, v)
        return st["regs"]["rip"]

    # ---- run ---------------------------------------------------------------------------------------------------
    def run(self, entry=0x3c38a, maxsec=600, resume=None, start_rip=None):
        mu = self.mu
        if start_rip:
            rip = start_rip
        elif resume:
            rip = self.restore(resume)
        else:
            rsp = STACK + STACK_SZ - 0x4000
            self.w("rsp", rsp - 8)
            self.wq(rsp - 8, SENT + 0x100)
            self.w("rdx", 0)
            rip = BASE + entry
        t0 = self.t0 = time.time()
        self.state = "run"
        while not self.stop:
            try:
                mu.emu_start(rip, 0)
            except UcError as e:
                if self.pending is None:
                    print("UC error", e, "rip=%x" % (self.r("rip") - BASE), flush=True)
                    break
            if self.state == "main_done" and self.pending is None:
                print("MAIN RETURNED rax=%x icount=%d t=%.1f" % (self.r("rax"), self.icount, time.time() - t0), flush=True)
                break
            if self.pending is not None:
                self.deliver()
                rip = self.r("rip")
                continue
            if getattr(self, "watch_hit", False):
                self.watch_hit = False
                rip = self.r("rip")
                print("WATCH rip=%x rsp=%x t=%.0f regs %s" % (rip - BASE, self.r("rsp"), time.time() - t0,
                      " ".join("%s=%x" % (n, self.r(n)) for n in ("rax", "rcx", "rdx", "rbx", "rsi", "rdi", "r8", "r9"))), flush=True)
                continue
            print("emu stopped rip=%x" % (self.r("rip") - BASE), flush=True)
            break
            if time.time() - t0 > maxsec:
                print("timeout"); break
        print("done icount", self.icount, "t=%.1f" % (time.time() - t0), flush=True)


if __name__ == "__main__":
    import re
    a = sys.argv[1:]
    flag = a[0] if a else "flag{00000000000000000000000000000000}"
    e = Emu(flag, log="--log" in a, maxinsn=int(a[a.index("--max") + 1]) if "--max" in a else 0)
    if "--snapat" in a:
        rva, path = a[a.index("--snapat") + 1].split(":")

        def _snap(em, p=path):
            em.snapshot(p); em.stop = True; em.mu.emu_stop()
        e.add_bp(int(rva, 16), _snap)
    if "--fast1080" in a:
        import h_sha1fast
        def mk_fast(fn):
            def _f(em):
                rcx, rdx = em.r("rcx"), em.r("rdx")
                if rdx != M64:
                    print("%x with rdx=%x from %x" % (fn, rdx, em.q(em.r("rsp")) - BASE), flush=True)
                    return
                d = bytes(em.mu.mem_read(rcx, 0x58))
                if fn == 0x2b840 and LOG2B:
                    print("EV2B from %x st %s W %s" % (em.q(em.r("rsp")) - BASE, d[:20].hex(), " ".join("%08x" % x for x in struct.unpack("<16I", d[0x18:0x58]))), flush=True)
                out = h_sha1fast.compress(fn, struct.unpack("<5I", d[:20]), struct.unpack("<16I", d[0x18:0x58]))
                em.mu.mem_write(rcx, struct.pack("<5I", *out))
                r = em.q(em.r("rsp"))
                em.w("rsp", em.r("rsp") + 8)
                em.w("rip", r)
            return _f
        for fn in h_sha1fast.VARIANT:
            e.add_bp(fn, mk_fast(fn))
    if "--probe" in a:
        import re, h_sha1fast
        cnt, cur, same = {}, {}, {}

        def mk_in(fn):
            def _i(em):
                n = cnt[fn] = cnt.get(fn, 0) + 1
                rcx, rdx = em.r("rcx"), em.r("rdx")
                d = bytes(em.mu.mem_read(rcx, 0x58))
                cur[fn] = (rcx, d)
                if n <= 3:
                    print("CALL %x #%d from %x rdx=%x IN %s" % (fn, n, em.q(em.r("rsp")) - BASE, rdx, d.hex()), flush=True)
            return _i

        def mk_out(fn):
            def _o(em):
                rcx, d = cur[fn]
                o = bytes(em.mu.mem_read(rcx, 0x58))
                exp = struct.pack("<5I", *h_sha1fast.rounds(struct.unpack("<5I", d[:20]), struct.unpack("<16I", d[0x18:0x58])))
                eq = exp == o[:20]
                same[fn] = same.get(fn, 0) + (1 if eq else 0)
                if cnt[fn] <= 3 or not eq and cnt[fn] < 12:
                    print("RET  %x #%d OUT %s plain_sha1=%s other_bytes_changed=%s" % (fn, cnt[fn], o.hex(), eq, o[20:] != d[20:]), flush=True)
                if cnt[fn] % 2000 == 0:
                    print("  %x calls %d plain %d" % (fn, cnt[fn], same[fn]), flush=True)
            return _o
        for fn in (0x1dfc0, 0x2b840):
            if "HFAST" in os.environ and "%x:" % fn in os.environ["HFAST"]:
                continue
            e.add_bp(fn, mk_in(fn))
            for l in open("~/d30/hulud/fhuge.txt"):
                if "call     0x%x" % fn in l and l.rstrip().endswith("0x%x" % fn):
                    e.add_bp(int(l.split()[0], 16) + 5, mk_out(fn))
    if "--watch" in a:
        import threading
        sec = float(a[a.index("--watch") + 1])

        def _wd():
            while not e.stop:
                time.sleep(sec)
                e.watch_hit = True
                e.mu.emu_stop()
        threading.Thread(target=_wd, daemon=True).start()
    if "--blocks" in a:
        order, count = [], {}

        def _blk(mu, addr, size, ud):
            r = addr - BASE
            if r not in count:
                count[r] = 0
                order.append(r)
                if len(order) % 500 == 0:
                    print("  blocks", len(order), "%x t=%.1f" % (r, time.time() - e.t0), flush=True)
            count[r] += 1
        e.mu.hook_add(UC_HOOK_BLOCK, _blk, None, BASE + 0x3c38a, BASE + 0x5a1fa)

        def _save(em=None):
            with open(a[a.index("--blocks") + 1], "w") as f:
                for r in order:
                    f.write("%x %d\n" % (r, count[r]))
        import atexit
        atexit.register(_save)
    if "--tracefn" in a:
        # --tracefn <fn-rva>:<nth call>:<outfile> : record one call's executed instructions (rva, bytes)
        fn, nth, out = a[a.index("--tracefn") + 1].split(":")
        fn, nth = int(fn, 16), int(nth)
        tr, n = [], [0]
        rec = [False, 0]

        def _ins(mu, addr, size, ud):
            if rec[0]:
                tr.append((addr - BASE, bytes(mu.mem_read(addr, size))))

        def _en(em):
            n[0] += 1
            if n[0] == nth:
                rec[0] = True

        def _ret(em):
            if rec[0]:
                rec[0] = False
                import pickle
                pickle.dump(tr, open(out, "wb"))
                print("TRACE saved", len(tr), flush=True)
                em.stop = True
                em.mu.emu_stop()
        e.add_bp(fn, _en)
        for l in open("~/d30/hulud/fhuge.txt"):
            if l.rstrip().endswith("call     0x%x" % fn):
                e.add_bp(int(l.split()[0], 16) + 5, _ret)
        e.mu.hook_add(UC_HOOK_CODE, _ins, None, BASE + fn, BASE + fn + 0xfff0)
    if "--cmptest" in a:
        # compare one 0x1080 call against a plain SHA-1 round function
        seen = {}

        def _in(em):
            if "in" in seen: return
            rcx = em.r("rcx")
            seen["in"] = (rcx, bytes(em.mu.mem_read(rcx, 0x58)))

        def _out(em):
            if "out" in seen: return
            rcx, d = seen["in"]
            seen["out"] = bytes(em.mu.mem_read(rcx, 0x58))
            print("IN ", d.hex()); print("OUT", seen["out"].hex())
            em.stop = True; em.mu.emu_stop()
        e.add_bp(0x3ce5e, _in)
        e.add_bp(0x3ce63, _out)
    if "--cmp" in a:
        lim = int(a[a.index("--cmp") + 1])
        cnt = [0]

        def _c(em):
            cnt[0] += 1
            if cnt[0] <= lim:
                print("CMP#%d bl=%02x sil=%02x dl=%02x rdx=%x rsi=%x r8=%x width=%x" % (
                    cnt[0], em.r("rbx") & 255, em.r("rsi") & 255, em.r("rdx") & 255, em.r("rdx"), em.r("rsi"), em.r("r8"),
                    em.q(em.r("rbp") + 0x1070)), flush=True)

        def _d(em):
            print("END-ITEM ca8=%02x" % (em.q(em.r("rbp") + 0xca8) & 255), "cmps", cnt[0], flush=True)
        e.add_bp(0x59cd9, _c)
        e.add_bp(0x59ce9, _d)
    def _disk_ssn(em):
        # 0x6495d parses ntdll.dll from disk for the NtGetContextThread SSN; on a clean system it equals the in-memory one
        em.w("rax", 1)
        em.w("rdx", em.r("r12") & 0xffffffff)
        r = em.q(em.r("rsp"))
        em.w("rsp", em.r("rsp") + 8)
        em.w("rip", r)
    e.add_bp(0x6495d, _disk_ssn)
    if "--evid" in a:
        def _ev(em):
            b = em.r("rbp")
            print("EVIDENCE at %x: %s" % (em.r("rip") - BASE, bytes(em.mu.mem_read(b + 0x7d0, 8)).hex()), flush=True)
        e.add_bp(0x3f413, _ev)

        def _tm(em):
            print("TIMING verdict at %x: %x (rdtsc hook hits %d)" % (em.r("rip") - BASE, em.d(em.r("rbp") + 0x4e0), getattr(em, "nrdtsc", 0)), flush=True)
        e.add_bp(0x3f942, _tm)

        def _ta(em):
            print("TIMEARGS tsc=%x qpc=%x freq=%x kuser=%x" % (em.r("rcx"), em.r("rdx"), em.r("r8"), em.r("r9")), flush=True)
        e.add_bp(0x3d6dc, _ta)
        e.add_bp(0x43eb1, _ta)

        def _tr(em):
            print("TIMERET %x" % (em.r("rax") & 0xffffffff), flush=True)
        e.add_bp(0x43eb6, _tr)
        e.add_bp(0x3d6e1, _tr)
        e.add_bp(0x45bae - 0x19 + 0x19, _ev)
    if "--pairs" in a:
        seen = {}

        def mk_pair(base, idx):
            def _pair(em):
                addr = em.r("rip") - BASE
                b, i = em.r("rbp"), em.r(idx)
                v, x = em.q(b + i + base), em.q(b + i + base + 8)
                seen[(addr, i)] = seen.get((addr, i), 0) + 1
                if seen[(addr, i)] == 1:
                    print("PAIR %x [%x] value=%x expected=%x %s" % (addr, i, v, x, "OK" if v == x else "*** MISMATCH"), flush=True)
            return _pair
        lines = open("~/d30/hulud/fhuge.txt").read().splitlines()
        pat = re.compile(r"^\s*([0-9a-f]+)\s+(?:mov|add)\s+\w+, qword ptr \[rbp \+ (rax|rcx) \+ (0x[0-9a-f]+)\]")
        hooked = set()
        for n, l in enumerate(lines):
            m = pat.search(l)
            if not m:
                continue
            for j in range(n + 1, min(n + 26, len(lines))):
                m2 = pat.search(lines[j])
                if m2 and m2.group(2) == m.group(2) and int(m2.group(3), 16) == int(m.group(3), 16) + 8:
                    rv = int(m.group(1), 16)
                    if rv not in hooked:
                        hooked.add(rv)
                        e.add_bp(rv, mk_pair(int(m.group(3), 16), m.group(2)))
                    break
    if "--crypt" in a:
        # capture per-block keys and block values of both cipher passes, plus the stored target of each candidate
        rec = {"p1": [], "p2": [], "items": [], "cur": []}

        def _p1in(em):
            b = em.r("rbp")
            rec["p1"].append(dict(k=[em.q(b + 0x710), em.q(b + 0x718)], s=[em.q(b + 0xd10), em.q(b + 0xd18)], n=em.q(b + 0xf68)))

        def _p1out(em):
            b = em.r("rbp")
            rec["p1"][-1]["o"] = [em.q(b + 0xd10), em.q(b + 0xd18)]

        def _p2in(em):
            b = em.r("rbp")
            rec["p2"].append(dict(k=[em.q(b + 0xd10), em.q(b + 0xd18)], s=[em.q(b + 0xcc0), em.q(b + 0xcc8)], r12=em.r("r12"), off=em.q(b + 0xd28)))

        def _p2out(em):
            b = em.r("rbp")
            rec["p2"][-1]["o"] = [em.q(b + 0xcc0), em.q(b + 0xcc8)]

        pa = [None]

        def _a(em):
            pa[0] = (em.r("rbx") & 255, em.r("rdx") & 255)

        def _cmp(em):
            rec["cur"].append((em.r("rbx") & 255, em.r("rsi") & 255, em.r("rdx") & 255) + pa[0])

        def _item(em):
            rec["items"].append(list(rec["cur"]))
            rec["cur"] = []
        e.add_bp(0x5855d, _p1in)
        e.add_bp(0x5868d, _p1out)
        e.add_bp(0x58877, _p2in)
        e.add_bp(0x589a0, _p2out)
        e.add_bp(0x590fb, _a)
        e.add_bp(0x59cd9, _cmp)
        e.add_bp(0x59ce9, _item)
        import atexit

        def _dump():
            json.dump(rec, open(a[a.index("--crypt") + 1], "w"))
        atexit.register(_dump)
    if "--newinput" in a:
        new = a[a.index("--newinput") + 1].encode()
        rip = e.restore(a[a.index("--resume") + 1])
        rbp = e.r("rbp")
        ptr = e.q(rbp + 0x1148)
        e.mu.mem_write(ptr, new)
        e.wq(rbp + 0x4d0, len(new))
        e.wq(rbp + 0x188, len(new))
        e.run(resume=None, start_rip=rip)
    else:
        e.run(resume=a[a.index("--resume") + 1] if "--resume" in a else None)
    print(repr(e.output))
    from collections import Counter
    print(Counter(e.calls).most_common(60))
