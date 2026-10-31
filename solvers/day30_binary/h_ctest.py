"""Check h_cipher against the blocks captured by h_emu.py --crypt; print each candidate's stored target."""
import json, sys
import h_cipher as c

r = json.load(open(sys.argv[1]))
print("p1 blocks", len(r["p1"]), "p2 blocks", len(r["p2"]), "items", len(r["items"]), [len(i) for i in r["items"]])
ok = True
for i, b in enumerate(r["p1"]):
    rc0 = 0x40714d53b9553253
    o = c.enc(c.P1, b["k"], b["s"], rc0)
    back = c.dec(c.P1, b["k"], b["o"], rc0)
    print("P1 #%d n=%d k=%016x%016x in=%016x%016x out=%016x%016x model=%s inv=%s" % (
        i, b["n"], *b["k"], *b["s"], *b["o"], o == b["o"], back == b["s"]))
n = r["p1"][0]["n"] if r["p1"] else 0
for i, b in enumerate(r["p2"]):
    rc0 = b["r12"]
    o = c.enc(c.P2, b["k"], b["s"], rc0)
    back = c.dec(c.P2, b["k"], b["o"], rc0)
    print("P2 #%d off=%x r12=%x k=%016x%016x in=%016x%016x out=%016x%016x model=%s inv=%s" % (
        i, b["off"], b["r12"], *b["k"], *b["s"], *b["o"], o == b["o"], back == b["s"]))
for i, it in enumerate(r["items"]):
    c2 = bytes(x[3] for x in it)
    t = bytes(x[1] ^ x[2] ^ x[4] for x in it)
    print("ITEM", i, "len", len(it), "target", t.hex())
    print("  c2raw ", c2.hex())
