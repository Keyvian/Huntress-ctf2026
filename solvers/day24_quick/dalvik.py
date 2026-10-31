"""Minimal Dalvik (DEX) bytecode INTERPRETER in pure Python, for Day-23 mobile 'Hook Line and Signal' (puzzle schema v2,
codec "analysis": the APK carries no data field; the answer is what `Release.code(Context)` would compute - a chain of 64-bit
mixing functions over constants, with brute-force "probe" loops and decoy functions that are never called).
We never execute artifact code: the DEX is parsed (strings / types / protos / methods / fields / class_data / code_items) and
the static methods are interpreted with Java int/long wrap-around semantics. Supported: moves, consts, goto, if-*, cmp-long,
all int/long binops (normal, /2addr, /lit8, /lit16), unary ops / casts, sget/sput (static_values + lazy <clinit>),
invoke-static/direct/virtual (+/range), and a tiny Java library model (StringBuilder, String, Long/Integer.toHexString,
Math.*). Unknown opcodes raise UnsupportedOpcode naming the opcode so a new variant fails loudly instead of guessing.
usage: dalvik.py <classes.dex | apk> [Class->method]"""
import struct, sys, os, io, zipfile, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # so `import native` works under `python -I` too

MASK32, MASK64 = 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF


def s32(v):
    v &= MASK32
    return v - (1 << 32) if v & 0x80000000 else v


def s64(v):
    v &= MASK64
    return v - (1 << 64) if v & 0x8000000000000000 else v


def jdiv(a, b, bits):
    if b == 0:
        raise ZeroDivisionError("ArithmeticException: / by zero")
    q = abs(a) // abs(b)
    if (a < 0) != (b < 0):
        q = -q
    return s32(q) if bits == 32 else s64(q)


def jrem(a, b, bits):
    if b == 0:
        raise ZeroDivisionError("ArithmeticException: % by zero")
    return a - jdiv(a, b, bits) * b


class UnsupportedOpcode(Exception):
    pass


def _uleb(b, o):
    v = 0; s = 0
    while True:
        c = b[o]; o += 1
        v |= (c & 0x7f) << s; s += 7
        if not c & 0x80:
            return v, o


class Dex:
    def __init__(self, b):
        if b[:2] == b"PK":
            z = zipfile.ZipFile(io.BytesIO(b))
            b = z.read("classes.dex")
        assert b[:4] == b"dex\n", "not a dex"
        self.b = b
        u32 = lambda o: struct.unpack_from("<I", b, o)[0]
        n, off = u32(0x38), u32(0x3c)
        self.strings = []
        for i in range(n):
            so = u32(off + 4 * i)
            _, p = _uleb(b, so)
            e = b.index(b"\x00", p)
            self.strings.append(b[p:e].decode("utf-8", "replace"))  # MUTF-8 ~ UTF-8 for our ASCII needs
        n, off = u32(0x40), u32(0x44)
        self.types = [self.strings[u32(off + 4 * i)] for i in range(n)]
        n, off = u32(0x48), u32(0x4c)
        self.protos = []
        for i in range(n):
            sh, rt, po = struct.unpack_from("<III", b, off + 12 * i)
            params = []
            if po:
                cnt = u32(po)
                params = [self.types[struct.unpack_from("<H", b, po + 4 + 2 * k)[0]] for k in range(cnt)]
            self.protos.append((self.strings[sh], self.types[rt], params))
        n, off = u32(0x50), u32(0x54)
        self.fields = []
        for i in range(n):
            c, t, nm = struct.unpack_from("<HHI", b, off + 8 * i)
            self.fields.append((self.types[c], self.types[t], self.strings[nm]))
        n, off = u32(0x58), u32(0x5c)
        self.methods = []
        for i in range(n):
            c, p, nm = struct.unpack_from("<HHI", b, off + 8 * i)
            self.methods.append((self.types[c], self.protos[p], self.strings[nm]))
        n, off = u32(0x60), u32(0x64)
        self.classes = {}
        for i in range(n):
            cls, acc, sup, ifs, src, ann, cdata, svals = struct.unpack_from("<8I", b, off + 32 * i)
            cname = self.types[cls]
            info = {"name": cname, "super": self.types[sup] if sup != 0xFFFFFFFF else None, "static_fields": [],
                    "methods": {}, "statics": {}, "clinit": None, "initialized": False}
            if cdata:
                o = cdata
                nsf, o = _uleb(b, o); nif, o = _uleb(b, o); nd, o = _uleb(b, o); nv, o = _uleb(b, o)
                fidx = 0
                for _ in range(nsf):
                    d, o = _uleb(b, o); _af, o = _uleb(b, o); fidx += d
                    info["static_fields"].append(self.fields[fidx])
                fidx = 0
                for _ in range(nif):
                    d, o = _uleb(b, o); _af, o = _uleb(b, o); fidx += d
                for cnt in (nd, nv):  # direct methods, then virtual methods: each list restarts its index delta at 0
                    midx = 0
                    for _ in range(cnt):
                        d, o = _uleb(b, o); _af, o = _uleb(b, o); code_off, o = _uleb(b, o); midx += d
                        mc, mp, mn = self.methods[midx]
                        info["methods"][(mn, mp[0])] = code_off  # key: (name, shorty)
                        info["methods"].setdefault(mn, code_off)
                        if mn == "<clinit>":
                            info["clinit"] = code_off
            # default static values
            for f in info["static_fields"]:
                info["statics"][f[2]] = 0 if f[1] in "BCDFIJSZ" else None
            if svals:
                p = svals
                cnt, p = _uleb(b, p)
                for k in range(min(cnt, len(info["static_fields"]))):
                    v, p = self._encoded_value(p)
                    info["statics"][info["static_fields"][k][2]] = v
            self.classes[cname] = info

    def _encoded_value(self, p):
        b = self.b
        h = b[p]; p += 1
        vt, va = h & 0x1f, h >> 5
        if vt in (0x00, 0x02, 0x03, 0x04, 0x06):  # byte, short, char, int, long (sign-extended except char)
            raw = b[p:p + va + 1]; p += va + 1
            v = int.from_bytes(raw, "little", signed=(vt != 0x03))
            return v, p
        if vt in (0x10, 0x11):  # float / double (zero-extended to the right)
            raw = b[p:p + va + 1]; p += va + 1
            size = 4 if vt == 0x10 else 8
            raw = raw + b"\x00" * (size - len(raw))
            return struct.unpack("<f" if vt == 0x10 else "<d", raw)[0], p
        if vt in (0x17, 0x18, 0x19, 0x1a, 0x1b):  # string, type, field, method, enum (index)
            idx = int.from_bytes(b[p:p + va + 1], "little"); p += va + 1
            return (self.strings[idx] if vt == 0x17 else idx), p
        if vt == 0x1e:
            return None, p
        if vt == 0x1f:
            return bool(va), p
        if vt == 0x1c:  # array
            cnt, p = _uleb(b, p)
            arr = []
            for _ in range(cnt):
                v, p = self._encoded_value(p)
                arr.append(v)
            return arr, p
        raise UnsupportedOpcode("encoded value type 0x%02x" % vt)

    def code(self, off):
        b = self.b
        regs, ins, outs, tries, dbg, isz = struct.unpack_from("<HHHHII", b, off)
        insns = b[off + 16: off + 16 + 2 * isz]
        return regs, ins, insns

    def find_class(self, suffix):
        for n in self.classes:
            if n.endswith(suffix):
                return n
        return None


class JStringBuilder:
    def __init__(self, s=""):
        self.s = str(s)

    def __repr__(self):
        return "StringBuilder(%r)" % self.s


# ---- opcode tables -------------------------------------------------------------------------------------------------
INT_BIN = {0x90: "add", 0x91: "sub", 0x92: "mul", 0x93: "div", 0x94: "rem", 0x95: "and", 0x96: "or", 0x97: "xor",
           0x98: "shl", 0x99: "shr", 0x9a: "ushr"}
LONG_BIN = {0x9b: "add", 0x9c: "sub", 0x9d: "mul", 0x9e: "div", 0x9f: "rem", 0xa0: "and", 0xa1: "or", 0xa2: "xor",
            0xa3: "shl", 0xa4: "shr", 0xa5: "ushr"}
INT_2ADDR = {op + 0x20: nm for op, nm in INT_BIN.items()}     # 0xb0..0xba
LONG_2ADDR = {op + 0x20: nm for op, nm in LONG_BIN.items()}   # 0xbb..0xc5
LIT16 = {0xd0: "add", 0xd1: "rsub", 0xd2: "mul", 0xd3: "div", 0xd4: "rem", 0xd5: "and", 0xd6: "or", 0xd7: "xor"}
LIT8 = {0xd8: "add", 0xd9: "rsub", 0xda: "mul", 0xdb: "div", 0xdc: "rem", 0xdd: "and", 0xde: "or", 0xdf: "xor",
        0xe0: "shl", 0xe1: "shr", 0xe2: "ushr"}
IF2 = {0x32: "eq", 0x33: "ne", 0x34: "lt", 0x35: "ge", 0x36: "gt", 0x37: "le"}
IFZ = {0x38: "eq", 0x39: "ne", 0x3a: "lt", 0x3b: "ge", 0x3c: "gt", 0x3d: "le"}


def binop(nm, a, b, bits):
    if bits == 32:
        a, b = s32(a), s32(b)
        sh = b & 31
        if nm == "add": return s32(a + b)
        if nm == "sub": return s32(a - b)
        if nm == "rsub": return s32(b - a)
        if nm == "mul": return s32(a * b)
        if nm == "div": return jdiv(a, b, 32)
        if nm == "rem": return jrem(a, b, 32)
        if nm == "and": return s32(a & b)
        if nm == "or": return s32(a | b)
        if nm == "xor": return s32(a ^ b)
        if nm == "shl": return s32(a << sh)
        if nm == "shr": return s32(a >> sh)
        if nm == "ushr": return s32((a & MASK32) >> sh)
    else:
        a, b = s64(a), b
        if nm in ("shl", "shr", "ushr"):
            sh = s32(b) & 63
            if nm == "shl": return s64(a << sh)
            if nm == "shr": return s64(a >> sh)
            return s64((a & MASK64) >> sh)
        b = s64(b)
        if nm == "add": return s64(a + b)
        if nm == "sub": return s64(a - b)
        if nm == "mul": return s64(a * b)
        if nm == "div": return jdiv(a, b, 64)
        if nm == "rem": return jrem(a, b, 64)
        if nm == "and": return s64(a & b)
        if nm == "or": return s64(a | b)
        if nm == "xor": return s64(a ^ b)
    raise UnsupportedOpcode("binop " + nm)


def cmp(nm, a, b):
    return {"eq": a == b, "ne": a != b, "lt": a < b, "ge": a >= b, "gt": a > b, "le": a <= b}[nm]


class VM:
    def __init__(self, dex, max_steps=50_000_000, libs=None):
        self.dex = dex
        self.steps = 0
        self.max_steps = max_steps
        self.libs = libs or {}  # {"lib/<abi>/x.so": bytes} for `native` methods (JNI exports emulated by native.py)
        self.trace = []  # (class, method) calls made - lets the caller see which functions are REAL vs decoys

    # ---- class init / statics
    def _init_class(self, cname):
        c = self.dex.classes.get(cname)
        if c and not c["initialized"]:
            c["initialized"] = True
            if c["clinit"]:
                self.run(cname, "<clinit>", [], code_off=c["clinit"])

    def sget(self, fidx):
        cname, ftype, fname = self.dex.fields[fidx]
        self._init_class(cname)
        c = self.dex.classes.get(cname)
        if c is None:
            raise UnsupportedOpcode("sget on foreign class %s.%s" % (cname, fname))
        return c["statics"].get(fname)

    def sput(self, fidx, v):
        cname, ftype, fname = self.dex.fields[fidx]
        self._init_class(cname)
        c = self.dex.classes.get(cname)
        if c is not None:
            c["statics"][fname] = v

    # ---- library model for the few JDK calls these apps make
    def lib_call(self, cname, mname, shorty, args):
        if cname == "Ljava/lang/StringBuilder;":
            if mname == "<init>":
                args[0].s = str(args[1]) if len(args) > 1 and isinstance(args[1], str) else ""
                return None
            sb = args[0]
            if mname == "append":
                a = args[1]
                pt = shorty[1:]  # param shorty
                if pt == "C":
                    sb.s += chr(a & 0xFFFF)
                elif pt == "Z":
                    sb.s += "true" if a else "false"
                elif isinstance(a, JStringBuilder):
                    sb.s += a.s
                else:
                    sb.s += "null" if a is None else str(a)
                return sb
            if mname == "toString": return sb.s
            if mname == "length": return len(sb.s)
            if mname == "charAt": return ord(sb.s[args[1]])
            if mname == "reverse": sb.s = sb.s[::-1]; return sb
            if mname == "insert": sb.s = sb.s[:args[1]] + str(args[2]) + sb.s[args[1]:]; return sb
        if cname == "Ljava/lang/String;":
            s = args[0]
            if mname == "charAt": return ord(s[args[1]])
            if mname == "length": return len(s)
            if mname == "toUpperCase": return s.upper()
            if mname == "toLowerCase": return s.lower()
            if mname == "trim": return s.strip()
            if mname == "equals": return 1 if s == args[1] else 0
            if mname == "equalsIgnoreCase": return 1 if s.lower() == str(args[1]).lower() else 0
            if mname == "substring": return s[args[1]:] if len(args) == 2 else s[args[1]:args[2]]
            if mname == "concat": return s + args[1]
            if mname == "hashCode":
                h = 0
                for ch in s: h = s32(31 * h + ord(ch))
                return h
            if mname == "valueOf":
                a = args[0]
                return chr(a & 0xFFFF) if shorty[1:] == "C" else ("null" if a is None else str(a))
            if mname == "format":
                return str(args[0]) % tuple(args[1] or [])
        if cname in ("Ljava/lang/Long;", "Ljava/lang/Integer;"):
            bits = 64 if cname == "Ljava/lang/Long;" else 32
            m = MASK64 if bits == 64 else MASK32
            a = args[0]
            if mname == "toHexString": return "%x" % (a & m)
            if mname == "toBinaryString": return bin(a & m)[2:]
            if mname == "toOctalString": return "%o" % (a & m)
            if mname == "toString": return str(a)
            if mname == "valueOf": return a
            if mname in ("longValue", "intValue"): return a
            if mname == "rotateLeft":
                sh = args[1] & (bits - 1); v = a & m
                return (s64 if bits == 64 else s32)((v << sh) | (v >> (bits - sh)))
            if mname == "rotateRight":
                sh = args[1] & (bits - 1); v = a & m
                return (s64 if bits == 64 else s32)((v >> sh) | (v << (bits - sh)))
            if mname == "bitCount": return bin(a & m).count("1")
            if mname == "reverse":
                return (s64 if bits == 64 else s32)(int(bin(a & m)[2:].zfill(bits)[::-1], 2))
            if mname == "numberOfTrailingZeros":
                v = a & m
                return bits if v == 0 else (v & -v).bit_length() - 1
            if mname == "numberOfLeadingZeros":
                return bits - (a & m).bit_length()
            if mname == "parseLong" or mname == "parseInt":
                return int(args[0], args[1] if len(args) > 1 else 10)
        if cname == "Ljava/lang/Math;":
            a = args[0]
            if mname == "abs": return abs(a)
            if mname in ("max", "min"): return (max if mname == "max" else min)(a, args[1])
            if mname == "floorMod": return a % args[1]
        if cname == "Ljava/lang/Object;" and mname == "<init>":
            return None
        if cname == "Ljava/lang/System;":
            if mname in ("loadLibrary", "load", "gc", "runFinalization"):
                return None  # the JNI library is resolved lazily by native.py when a native method is invoked
            if mname == "identityHashCode":
                return 0
            if mname in ("currentTimeMillis", "nanoTime"):
                return 0
        raise UnsupportedOpcode("library call %s->%s%s" % (cname, mname, shorty))

    # ---- invoke dispatch
    def invoke(self, midx, args):
        cname, (shorty, rtype, params), mname = self.dex.methods[midx]
        c = self.dex.classes.get(cname)
        if c is not None and (mname, shorty) in c["methods"]:
            self._init_class(cname)
            self.trace.append((cname, mname))
            off = c["methods"][(mname, shorty)]
            if not off:  # `native` method: no code_item -> emulate the JNI export from the bundled lib/<abi>/*.so
                import native
                self.trace.append((cname, mname + "[JNI]"))
                return native.jni_call(self.libs, cname, mname, shorty, params, args)
            return self.run(cname, mname, args, code_off=off, params=params, static="static")
        # a virtual call on an app class instance whose method is defined in a superclass of the dex (walk up)
        cc = c
        while cc is not None and cc.get("super") in self.dex.classes:
            cc = self.dex.classes[cc["super"]]
            if (mname, shorty) in cc["methods"]:
                self.trace.append((cc["name"], mname))
                return self.run(cc["name"], mname, args, code_off=cc["methods"][(mname, shorty)], params=params)
        return self.lib_call(cname, mname, shorty, args)

    def run(self, cname, mname, args, code_off, params=None, static=None):
        """args: list of Python values for the params (an instance receiver first for non-static; wide values are ONE entry)."""
        dex = self.dex
        regs_n, ins_n, insns = dex.code(code_off)
        R = [0] * (regs_n + 2)
        # place args in the last ins_n registers; wide params take 2 slots
        if params is None:
            params = []
        pos = regs_n - ins_n
        # receiver (non-static): the method's ins include 'this'; we can't know staticness from code_item alone, infer by count
        nslots = sum(2 if p in ("J", "D") else 1 for p in params)
        has_this = (ins_n == nslots + 1)
        ai = 0
        if has_this:
            R[pos] = args[0]; pos += 1; ai = 1
        for p in params:
            R[pos] = args[ai]; ai += 1
            pos += 2 if p in ("J", "D") else 1
        pc = 0
        result = None
        b = insns
        n = len(b)

        def u16(o): return struct.unpack_from("<H", b, o)[0]
        def s16(o): return struct.unpack_from("<h", b, o)[0]
        def i32(o): return struct.unpack_from("<i", b, o)[0]
        def i64(o): return struct.unpack_from("<q", b, o)[0]

        while pc < n:
            self.steps += 1
            if self.steps > self.max_steps:
                raise RuntimeError("step budget exhausted (infinite loop?) in %s->%s" % (cname, mname))
            op = b[pc]; hi = b[pc + 1]
            A, B = hi & 0xF, hi >> 4  # 4-bit regs for 12x/11n/22b forms
            # ---- 10x / 11x / 12x
            if op == 0x00:  # nop (payload tables also start with 0x00 but we never fall through into them)
                pc += 2; continue
            if op in (0x01, 0x04, 0x07):  # move, move-wide, move-object (12x)
                R[A] = R[B]; pc += 2; continue
            if op in (0x02, 0x05, 0x08):  # /from16 (22x)
                R[hi] = R[u16(pc + 2)]; pc += 4; continue
            if op in (0x03, 0x06, 0x09):  # /16 (32x)
                R[u16(pc + 2)] = R[u16(pc + 4)]; pc += 6; continue
            if op in (0x0a, 0x0b, 0x0c):  # move-result*
                R[hi] = result; pc += 2; continue
            if op == 0x0d:  # move-exception
                R[hi] = None; pc += 2; continue
            if op == 0x0e: return None
            if op in (0x0f, 0x10, 0x11): return R[hi]
            # ---- consts
            if op == 0x12:  # const/4
                v = B if B < 8 else B - 16
                R[A] = v; pc += 2; continue
            if op == 0x13: R[hi] = s16(pc + 2); pc += 4; continue
            if op == 0x14: R[hi] = i32(pc + 2); pc += 6; continue
            if op == 0x15: R[hi] = s32(u16(pc + 2) << 16); pc += 4; continue
            if op == 0x16: R[hi] = s16(pc + 2); pc += 4; continue
            if op == 0x17: R[hi] = i32(pc + 2); pc += 6; continue
            if op == 0x18: R[hi] = i64(pc + 2); pc += 10; continue
            if op == 0x19: R[hi] = s64(u16(pc + 2) << 48); pc += 4; continue
            if op == 0x1a: R[hi] = dex.strings[u16(pc + 2)]; pc += 4; continue
            if op == 0x1b: R[hi] = dex.strings[i32(pc + 2) & MASK32]; pc += 6; continue
            if op == 0x1c: R[hi] = dex.types[u16(pc + 2)]; pc += 4; continue
            if op == 0x1f:  # check-cast
                pc += 4; continue
            if op == 0x22:  # new-instance
                t = dex.types[u16(pc + 2)]
                if t == "Ljava/lang/StringBuilder;":
                    R[hi] = JStringBuilder()
                elif t in dex.classes:
                    R[hi] = {"__class__": t}
                else:
                    raise UnsupportedOpcode("new-instance " + t)
                pc += 4; continue
            # ---- control flow
            if op == 0x28:
                off = hi if hi < 128 else hi - 256
                pc += 2 * off; continue
            if op == 0x29: pc += 2 * s16(pc + 2); continue
            if op == 0x2a: pc += 2 * i32(pc + 2); continue
            if op in (0x2b, 0x2c):  # packed / sparse switch
                key = R[hi]
                tb = pc + 2 * i32(pc + 2)
                ident = u16(tb); size = u16(tb + 2)
                target = None
                if ident == 0x0100:  # packed
                    first = i32(tb + 4)
                    if 0 <= key - first < size:
                        target = i32(tb + 8 + 4 * (key - first))
                else:  # sparse
                    keys = [i32(tb + 4 + 4 * k) for k in range(size)]
                    tgts = [i32(tb + 4 + 4 * size + 4 * k) for k in range(size)]
                    for kk, tt in zip(keys, tgts):
                        if kk == key: target = tt; break
                pc = pc + 2 * target if target is not None else pc + 6
                continue
            if op == 0x31:  # cmp-long
                a, c2 = s64(R[b[pc + 2]]), s64(R[b[pc + 3]])
                R[hi] = (a > c2) - (a < c2); pc += 4; continue
            if op in (0x2d, 0x2e, 0x2f, 0x30):
                a, c2 = R[b[pc + 2]], R[b[pc + 3]]
                R[hi] = (a > c2) - (a < c2); pc += 4; continue
            if op in IF2:
                if cmp(IF2[op], s64(R[A]) if not isinstance(R[A], str) else R[A], s64(R[B]) if not isinstance(R[B], str) else R[B]):
                    pc += 2 * s16(pc + 2)
                else:
                    pc += 4
                continue
            if op in IFZ:
                v = R[hi]
                v = 0 if v is None else (v if isinstance(v, int) else 1)
                if cmp(IFZ[op], s64(v), 0):
                    pc += 2 * s16(pc + 2)
                else:
                    pc += 4
                continue
            # ---- misc object ops
            if op in (0x1d, 0x1e):  # monitor-enter / monitor-exit
                pc += 2; continue
            if op == 0x20:  # instance-of
                R[A] = 1 if R[B] is not None else 0; pc += 4; continue
            if op == 0x27:  # throw
                raise RuntimeError("java throw in %s->%s: %r" % (cname, mname, R[hi]))
            # ---- arrays (Python lists; wide elements are plain ints)
            if op == 0x21:  # array-length
                R[A] = len(R[B]); pc += 2; continue
            if op == 0x23:  # new-array vA, vB, type@CCCC
                t = dex.types[u16(pc + 2)]
                R[A] = [0] * R[B] if t[1] in "BCDFIJSZ" else [None] * R[B]
                pc += 4; continue
            if op == 0x24:  # filled-new-array {vC..}, type (35c)
                cnt = B
                regs = [b[pc + 4] & 0xF, b[pc + 4] >> 4, b[pc + 5] & 0xF, b[pc + 5] >> 4, A][:cnt]
                result = [R[r] for r in regs]; pc += 6; continue
            if op == 0x25:  # filled-new-array/range (3rc)
                cnt = hi; first = u16(pc + 4)
                result = [R[r] for r in range(first, first + cnt)]; pc += 6; continue
            if op == 0x26:  # fill-array-data vAA, +BBBBBBBB
                tb = pc + 2 * i32(pc + 2)
                width = u16(tb + 2); size = struct.unpack_from("<I", b, tb + 4)[0]
                arr = R[hi]
                for k in range(size):
                    arr[k] = int.from_bytes(b[tb + 8 + k * width: tb + 8 + (k + 1) * width], "little", signed=(width != 2 or True))
                pc += 6; continue
            if 0x44 <= op <= 0x4a:  # aget*
                arr, idx = R[b[pc + 2]], R[b[pc + 3]]
                if not 0 <= idx < len(arr):
                    raise RuntimeError("ArrayIndexOutOfBounds %d/%d in %s->%s" % (idx, len(arr), cname, mname))
                R[hi] = arr[idx]; pc += 4; continue
            if 0x4b <= op <= 0x51:  # aput*
                arr, idx = R[b[pc + 2]], R[b[pc + 3]]
                if not 0 <= idx < len(arr):
                    raise RuntimeError("ArrayIndexOutOfBounds %d/%d in %s->%s" % (idx, len(arr), cname, mname))
                v = R[hi]
                if op == 0x4e: v = ((v & 0xFF) ^ 0x80) - 0x80          # aput-byte
                elif op == 0x4f: v = v & 0xFFFF                          # aput-char
                elif op == 0x50: v = ((v & 0xFFFF) ^ 0x8000) - 0x8000   # aput-short
                elif op == 0x4b: v = s32(v)                              # aput (int/float slot)
                arr[idx] = v; pc += 4; continue
            # ---- statics
            if 0x60 <= op <= 0x66:  # sget*
                R[hi] = self.sget(u16(pc + 2)); pc += 4; continue
            if 0x67 <= op <= 0x6d:  # sput*
                self.sput(u16(pc + 2), R[hi]); pc += 4; continue
            if 0x52 <= op <= 0x5f:  # iget / iput on app objects (dict-backed)
                fidx = u16(pc + 2); fname = dex.fields[fidx][2]
                obj = R[B]
                if op <= 0x58:
                    R[A] = obj.get(fname, 0) if isinstance(obj, dict) else 0
                else:
                    if isinstance(obj, dict): obj[fname] = R[A]
                pc += 4; continue
            # ---- invokes
            if 0x6e <= op <= 0x72:  # 35c
                midx = u16(pc + 2)
                cnt = B
                regs = [b[pc + 4] & 0xF, b[pc + 4] >> 4, b[pc + 5] & 0xF, b[pc + 5] >> 4, A][:cnt]
                result = self._do_invoke(midx, regs, R, op != 0x71)
                pc += 6; continue
            if 0x74 <= op <= 0x78:  # 3rc
                midx = u16(pc + 2); cnt = hi; first = u16(pc + 4)
                regs = list(range(first, first + cnt))
                result = self._do_invoke(midx, regs, R, op != 0x77)
                pc += 6; continue
            # ---- unary
            if 0x7b <= op <= 0x8f:
                v = R[B]
                if op == 0x7b: R[A] = s32(-v)
                elif op == 0x7c: R[A] = s32(~v)
                elif op == 0x7d: R[A] = s64(-v)
                elif op == 0x7e: R[A] = s64(~v)
                elif op == 0x81: R[A] = s32(v)            # int-to-long
                elif op == 0x84: R[A] = s32(v)            # long-to-int
                elif op == 0x8d: R[A] = ((v & 0xFF) ^ 0x80) - 0x80  # int-to-byte
                elif op == 0x8e: R[A] = v & 0xFFFF        # int-to-char
                elif op == 0x8f: R[A] = ((v & 0xFFFF) ^ 0x8000) - 0x8000  # int-to-short
                elif op in (0x82, 0x83, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c):
                    raise UnsupportedOpcode("float/double conversion 0x%02x" % op)
                else:
                    raise UnsupportedOpcode("unary 0x%02x" % op)
                pc += 2; continue
            # ---- binops
            if op in INT_BIN:
                R[hi] = binop(INT_BIN[op], R[b[pc + 2]], R[b[pc + 3]], 32); pc += 4; continue
            if op in LONG_BIN:
                R[hi] = binop(LONG_BIN[op], R[b[pc + 2]], R[b[pc + 3]], 64); pc += 4; continue
            if op in INT_2ADDR:
                R[A] = binop(INT_2ADDR[op], R[A], R[B], 32); pc += 2; continue
            if op in LONG_2ADDR:
                R[A] = binop(LONG_2ADDR[op], R[A], R[B], 64); pc += 2; continue
            if op in LIT16:
                R[A] = binop(LIT16[op], R[B], s16(pc + 2), 32); pc += 4; continue
            if op in LIT8:
                lit = b[pc + 3]; lit = lit - 256 if lit > 127 else lit
                R[hi] = binop(LIT8[op], R[b[pc + 2]], lit, 32); pc += 4; continue
            if 0xa6 <= op <= 0xaf or 0xc6 <= op <= 0xcf:
                raise UnsupportedOpcode("float/double arithmetic 0x%02x" % op)
            raise UnsupportedOpcode("opcode 0x%02x at %d in %s->%s" % (op, pc, cname, mname))
        return result

    def _do_invoke(self, midx, regs, R, has_receiver):
        cname, (shorty, rtype, params), mname = self.dex.methods[midx]
        args = []
        i = 0
        if has_receiver:
            args.append(R[regs[0]]); i = 1
        for p in params:
            args.append(R[regs[i]])
            i += 2 if p in ("J", "D") else 1
        return self.invoke(midx, args)


ANS = re.compile(r"ANS-[0-9A-F]{16}")


def find_entry(dex):
    """(class, method name, shorty) of the static String method that builds the ANS- code: prefer Release.code, else the
    method whose code references the 'ANS-' string constant."""
    rel = dex.find_class("/Release;")
    if rel:
        for (k, off) in dex.classes[rel]["methods"].items():
            if isinstance(k, tuple) and k[0] == "code":
                return rel, k[0], k[1]
    ans_idx = dex.strings.index("ANS-") if "ANS-" in dex.strings else None
    for cname, c in dex.classes.items():
        for k, off in c["methods"].items():
            if not isinstance(k, tuple) or not off:
                continue
            regs, ins, insns = dex.code(off)
            for o in range(0, len(insns) - 3, 2):
                if insns[o] == 0x1a and struct.unpack_from("<H", insns, o + 2)[0] == ans_idx:
                    return cname, k[0], k[1]
    return None


def answer(dexbytes, entry=None, libs=None):
    """dexbytes may be a classes.dex or a whole APK (then lib/<abi>/*.so are collected for native methods)."""
    libs = dict(libs or {})
    if dexbytes[:2] == b"PK":
        z = zipfile.ZipFile(io.BytesIO(dexbytes))
        for n in z.namelist():
            if n.startswith("lib/") and n.endswith(".so"):
                libs.setdefault(n, z.read(n))
    dex = Dex(dexbytes)
    if entry:
        cname, mname = entry.split("->")
        cls = dex.find_class(cname) or cname
        key = next(k for k in dex.classes[cls]["methods"] if isinstance(k, tuple) and k[0] == mname)
        cname, mname, shorty = cls, key[0], key[1]
    else:
        e = find_entry(dex)
        if not e:
            raise RuntimeError("no ANS- building method found")
        cname, mname, shorty = e
    c = dex.classes[cname]
    off = c["methods"][(mname, shorty)]
    midx = next(i for i, (mc, mp, mn) in enumerate(dex.methods) if mc == cname and mn == mname and mp[0] == shorty)
    params = dex.methods[midx][1][2]
    vm = VM(dex, libs=libs)
    vm._init_class(cname)
    args = [None for _ in params]  # Context etc. -> null (never dereferenced by the arithmetic)
    r = vm.run(cname, mname, args, code_off=off, params=params)
    return r, vm


if __name__ == "__main__":
    data = open(sys.argv[1], "rb").read()
    r, vm = answer(data, sys.argv[2] if len(sys.argv) > 2 else None)
    print("RESULT", r, "valid" if isinstance(r, str) and ANS.fullmatch(r) else "INVALID", "steps", vm.steps)
    seen = []
    for t in vm.trace:
        if t not in seen: seen.append(t)
    print("called:", ", ".join("%s.%s" % (c.rsplit("/", 1)[-1].rstrip(";"), m) for c, m in seen))
    dex = vm.dex
    allm = [(c, k[0]) for c, ci in dex.classes.items() for k in ci["methods"] if isinstance(k, tuple) and ci["methods"][k]]
    dec = [(c, m) for c, m in allm if (c, m) not in vm.trace and m not in ("<init>", "onCreate", "proof", "code", "<clinit>")]
    print("never called (decoys):", ", ".join("%s.%s" % (c.rsplit("/", 1)[-1].rstrip(";"), m) for c, m in dec))
