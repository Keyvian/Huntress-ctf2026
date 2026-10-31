import sys, os
W = os.path.expanduser('~/ctf/day30_extra/')
lo, hi = int(sys.argv[1], 16), int(sys.argv[2], 16)
for line in open(W + 'full.txt'):
    a = int(line.split(':', 1)[0], 16)
    if lo <= a <= hi:
        print(line.rstrip()[:96])
