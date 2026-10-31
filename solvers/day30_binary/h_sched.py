"""Recover the message-schedule taps of a protected SHA-1 routine from its reduced round listing (h_rounds.py output)."""
import re, sys

lines = open(sys.argv[1]).read().splitlines()
txt = " ; ".join(lines)
slot = {}
for off, s in re.findall(r"mov e\w+, dword ptr \[r15 \+ (0x[0-9a-f]+)\] ; mov dword ptr \[rcx ([+-] (?:0x)?[0-9a-f]+)\]", txt):
    o = int(off, 16)
    if 0x18 <= o < 0x58:
        slot[s.replace(" ", "")] = (o - 0x18) // 4
print("W slots", sorted(slot.items(), key=lambda kv: kv[1]))
hist = {}
t = 16
for l in lines:
    m = re.search(r"(\w+), dword ptr \[rcx ([+-] (?:0x)?[0-9a-f]+)\] ; xor \1, dword ptr \[rcx ([+-] (?:0x)?[0-9a-f]+)\] ; xor \1, dword ptr \[rcx ([+-] (?:0x)?[0-9a-f]+)\] ; xor \1, dword ptr \[rcx ([+-] (?:0x)?[0-9a-f]+)\] ; rol \1, (\w+) ; mov dword ptr \[rcx ([+-] (?:0x)?[0-9a-f]+)\]", l)
    if not m:
        continue
    src = [slot.get(x.replace(" ", ""), "?") for x in m.groups()[1:5]]
    dst = slot.get(m.group(7).replace(" ", ""), "?")
    rot = m.group(6)
    # the slot holding W[t-k] has index (t-k) mod 16 in the rolling 16-word window
    taps = sorted((t - x) % 16 or 16 for x in src if x != "?")
    hist[(tuple(taps), rot)] = hist.get((tuple(taps), rot), 0) + 1
    if t < 19:
        print("t", t, "src", src, "dst", dst, "rol", rot, "taps", taps)
    t += 1
print("schedule rounds", t - 16, hist)
