"""Decrypt the six stored candidates of sha1-hulud.exe.
Forward transform for an n-block message M[0..n-1] (M = u64le length || normalized input || zero padding):
  phase 1: C1[i] = E1(K[i], M[i] ^ C1[i-1]), C1[-1] = 0; K[i+1] comes from a SHA-1-variant state absorbing M[i] and C1[i]
  phase 2: C2[i] = E2(K2, C1[i] ^ C2[i+1], rc(i)), C2[n] = 0, walking i = n-1 .. 0
C2 is compared with the stored target. Both ciphers invert, so each block is recovered in turn; the emulator supplies
K[i] for the known prefix (it runs from the post-integrity snapshot, so nothing is executed natively)."""
import json, os, struct, subprocess, sys
import h_cipher as c

M64 = (1 << 64) - 1
EMU = os.path.join(os.path.dirname(os.path.abspath(__file__)), "h_emu.py")
SNAP = "~/d30/hulud/snap_input.pkl"
PY = "~/ctf-venv/bin/python"
TMP = "~/d30/hulud/cs.json"


def emu(inp):
    env = dict(os.environ, PYTHONPATH=os.path.dirname(EMU))
    out = subprocess.run([PY, EMU, "x", "--fast1080", "--resume", SNAP, "--newinput", inp, "--crypt", TMP],
                         env=env, capture_output=True, text=True, timeout=120, errors="replace").stdout
    r = json.load(open(TMP))
    groups, cur = [], None
    for b in r["p1"]:
        if cur is None or len(cur) == cur[0]["n"]:
            cur = []
            groups.append(cur)
        cur.append(b)
    return r, groups, out


def blocks(t):
    return [list(struct.unpack("<QQ", t[i:i + 16])) for i in range(0, len(t), 16)]


def rc2(n, i):
    return (0x33c3366c503e1720 * n + 0x7ddae3471243d999 + (n - 1 - i) * 0xcc3cc993afc1e8e0) & M64


def main():
    r0, g0, _ = emu("flag{00000000000000000000000000000000}")
    K2 = r0["p2"][0]["k"]
    targets = [bytes(x[1] ^ x[2] ^ x[4] for x in it) for it in r0["items"]]
    results = []
    for idx, t in enumerate(targets):
        n = len(t) // 16
        C2 = blocks(t)
        C1 = [None] * n
        chain = [0, 0]
        for i in range(n - 1, -1, -1):
            d = c.dec(c.P2, K2, C2[i], rc2(n, i))
            C1[i] = [d[0] ^ chain[0], d[1] ^ chain[1]]
            chain = C2[i]
        stream = b""
        prev = [0, 0]
        for i in range(n):
            if i == 0:
                k = g0[idx][0]["k"]
            else:
                L = struct.unpack("<Q", stream[:8])[0]
                body = stream[8:]
                probe = body + b"a" * max(0, min(L, 200) - len(body))
                try:
                    _, g, _ = emu(probe.decode("latin-1"))
                    k = g[idx][i]["k"]
                except Exception as ex:
                    print("  item", idx, "block", i, "emu failed:", ex, repr(probe[:60]))
                    break
            x = c.dec(c.P1, k, C1[i], 0x40714d53b9553253)
            m = [x[0] ^ prev[0], x[1] ^ prev[1]]
            stream += struct.pack("<QQ", *m)
            prev = C1[i]
            print("  item %d block %d/%d M=%s" % (idx, i, n, stream[-16:].hex()), repr(stream[-16:]), flush=True)
            if i == 0 and struct.unpack("<Q", stream[:8])[0] > 4096:
                print("  item", idx, "length field implausible, stopping")
                break
        L = struct.unpack("<Q", stream[:8])[0]
        print("ITEM", idx, "n", n, "len", L, repr(stream[8:8 + min(L, 200)]), flush=True)
        results.append((idx, n, L, stream))
    json.dump([(i, n, L, s.hex()) for i, n, L, s in results], open("~/d30/hulud/results.json", "w"))


main()
