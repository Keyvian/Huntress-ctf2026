"""Verify the protected-routine models against captured IN/OUT pairs: h_chk.py <probe log>."""
import re, struct, sys
import h_sha1fast

pending, res = {}, {}
for l in open(sys.argv[1]):
    m = re.match(r"CALL ([0-9a-f]+) #(\d+) from \w+ rdx=\w+ IN ([0-9a-f]+)", l)
    if m:
        pending[int(m.group(1), 16)] = bytes.fromhex(m.group(3))
        continue
    m = re.match(r"RET  ([0-9a-f]+) #(\d+) OUT ([0-9a-f]+)", l)
    if m:
        fn = int(m.group(1), 16)
        IN, OUT = pending[fn], bytes.fromhex(m.group(3))
        got = h_sha1fast.compress(fn, struct.unpack("<5I", IN[:20]), struct.unpack("<16I", IN[0x18:0x58]))
        ok = got == struct.unpack("<5I", OUT[:20])
        back = h_sha1fast.rev_rounds(got, struct.unpack("<16I", IN[0x18:0x58]), **h_sha1fast.VARIANT[fn])
        res.setdefault(fn, []).append((ok, back == struct.unpack("<5I", IN[:20])))
for fn, r in res.items():
    print("%x pairs %d model_ok %d inverse_ok %d" % (fn, len(r), sum(a for a, _ in r), sum(b for _, b in r)))
