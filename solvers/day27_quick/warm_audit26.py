"""Audit of a `warm26.py local <dir>` run over the mastery blobs: exact (case-sensitive) template match per blob, slug-word
frequencies (a wrong row decode yields a one-off non-word) and the row structure of each blob (26 `NN\\t` rows, BF row = 26).
usage: warm_audit26.py <local_output.txt> <blob dir>"""
import sys, re, os, collections

T = "Nice work decoding this warmup! To solve, submit this exact answer to the Game Master: "
rows = [l.rstrip("\n") for l in open(sys.argv[1], encoding="utf-8", errors="replace") if l.startswith("blob-")]
print("decoded lines:", len(rows))
words = [collections.Counter() for _ in range(3)]
bad = []
slugs = {}
for l in rows:
    name, rest = l.split(" ", 1)
    slug, msg = rest.split(" | ", 1)
    slugs[name] = slug
    if not msg.startswith(T):
        bad.append((name, "TEMPLATE", msg[:110]))
    elif msg[len(T):].rstrip(".") != slug:
        bad.append((name, "TAIL", msg[len(T):]))
    w = slug.split("-")
    for i in range(3):
        words[i][w[i]] += 1
print("non-exact:", bad[:20])
for i in range(3):
    once = sorted(w for w, c in words[i].items() if c == 1)
    print("pos", i, "distinct", len(words[i]), "singletons", len(once), once[:60])
d = sys.argv[2]
odd = []
codec_hint = collections.Counter()
for fn in sorted(os.listdir(d)):
    s = open(os.path.join(d, fn), "rb").read().decode("utf-8", "replace")
    ls = [x for x in s.splitlines() if x.strip()]
    labs = [x.split("\t", 1)[0] for x in ls]
    if len(ls) != 26 or labs != ["%02d" % i for i in range(1, 27)]:
        odd.append((fn, len(ls), labs[:30]))
    bfrows = [x.split("\t", 1)[0] for x in ls
              if re.fullmatch(r"[+\-<>\[\].,\s]+", x.split("\t", 1)[1]) and sum(c in "+-<>[]" for c in x) >= 8]
    if bfrows != ["26"]:
        odd.append((fn, "bfrows", bfrows))
print("odd structure:", odd[:20])
