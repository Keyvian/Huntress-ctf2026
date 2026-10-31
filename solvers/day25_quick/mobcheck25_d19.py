"""Independent re-implementation (Java 64-bit semantics) of the Day-25 mastery set-7 APK (Day-19 'Reflection Maze' theme,
com.huntress.mobile.d19.ve1c2da46cdd5, case MOB-19-E1C2DA46CD) from its jadx output. dalvik.py cannot run it because
Util.routeMazee3 dispatches through Class.forName(...).getDeclaredMethod("m" + ReflectionMaze.dispatch(k), Long.TYPE).invoke:
dispatch(0)=3, dispatch(1)=7, so the route is m3(m7(m7(m3(m7(j))))). Constants copied from the decompiled classes."""
M = (1 << 64) - 1


def u(x): return x & M
def rotl(x, n): x &= M; n %= 64; return ((x << n) | (x >> (64 - n))) & M
def ushr(x, n): return (x & M) >> n
def mul(a, b): return (a * b) & M
def add(a, b): return (a + b) & M
def sub(a, b): return (a - b) & M


def mixHop6f(j):
    j2 = mul(u(j) ^ u(-3089840100639886844), 4253859368694403081)
    j3 = sub(rotl(j2, 10), 7207836379136041726) ^ u(-7907246480460495490)
    return add(j3 ^ ushr(j3, 7), 2148237891224764961)


def m0(j):
    j2 = add(j, 1361831284002343836)
    j3 = j2 ^ ushr(j2, 28)
    j4 = rotl(j3, 45)
    return mul(j4 ^ ushr(j4, 29), -3522084747843672333)


def m3(j):
    j2 = u(j) ^ u(4888384627180490925) ^ u(8136025447018586579)
    return mul(rotl(j2, 20) ^ u(6982339811265028238), -3359519879058395155)


def m7(j):
    j2 = add(u(j) ^ u(3105295766629846616), 396392400719799768)
    return mul(mul(sub(add(rotl(j2, 6), 2023757653968653942), 7974843855001155426), 5384090593051707065), 8562111210843352631)


def dispatch(i):
    return {0: 3, 1: 7}.get(i, -1)


MZ = {3: m3, 7: m7, 0: m0}


def routeMazee3(j):
    v1 = MZ[dispatch(1)](j)
    v2 = MZ[dispatch(0)](v1)
    v3 = MZ[dispatch(1)](v2)
    v4 = MZ[dispatch(1)](v3)
    return MZ[dispatch(0)](v4)


def mixHop67(j):
    j2 = mul(u(j) ^ u(1927611535577409257), 194233973048730879)
    return rotl(j2, 50) ^ u(5978239145868513693)


def f1(j):
    j2 = add(mul(sub(u(j), 1613124350806307215), -1491036544797789731), 8330436342407045043)
    j3 = sub(rotl(j2, 23), 1311153594213640814)
    j4 = j3 ^ ushr(j3, 19)
    return sub(j4 ^ ushr(j4, 41), 7148751377419508481)


def finReflect96(j):
    j2 = u(j) ^ u(9193890448055953082)
    j3 = sub(rotl(j2, 22), 2426498481680707186)
    return sub(sub(mul(mul(j3 ^ ushr(j3, 20), 3661685156333707837), 7701026563466557401), 2067799567832954733), 8864450245889263048)


def token():
    return mixHop67(routeMazee3(mixHop6f(u(5264502812172079634))))


def code():
    v = finReflect96(f1(token())) ^ u(-6766633348880043390)
    return "ANS-" + "".join("0123456789ABCDEF"[(v >> i) & 15] for i in range(60, -1, -4))


if __name__ == "__main__":
    t = token()
    print("token %016x proof %x code %s" % (t, t, code()))
