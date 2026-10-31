"""Reduce a protected-routine trace to its round body: keep the 32-bit dataflow, drop the code-decrypt stubs.
h_rounds.py <trace.txt> : one line per round (a chunk between two decrypt stubs), rcx-relative slots -> names."""
import re, sys

lines = open(sys.argv[1]).read().splitlines()
chunks, cur = [], []
for l in lines:
    m = re.match(r"\s*([0-9a-f]+)\s+(\S+)\s*(.*)$", l)
    if not m:
        continue
    addr, mn, ops = m.group(1), m.group(2), m.group(3)
    if mn == "nop":
        if cur:
            chunks.append(cur); cur = []
        continue
    is32 = re.search(r"\b(eax|ecx|edx|ebx|esi|edi|r\d+d)\b", ops) and not re.search(r"\b(r\d+|rax|rbx|rdi|rsi|rbp)\b,", ops)
    if is32:
        cur.append("%s %s" % (mn, ops))
if cur:
    chunks.append(cur)
for i, c in enumerate(chunks):
    print(i, " ; ".join(c))
