"""Probe helper for untimed banking: submit computed answers for ids matching a regex minus excluded fields,
then try candidate values for single fields.  usage:
  sprobe.py <challenge> <answers.json> bank <include-regex> [exclude-regex]
  sprobe.py <challenge> <answers.json> try <answer_id> <cand1> <cand2> ..."""
import sys, json, time, re
sys.path.insert(0, "~/ctf")
from gm import GM
g = GM()
ch, af, mode = sys.argv[1], sys.argv[2], sys.argv[3]
ans = json.load(open(af))


def sub(d):
    for t in range(6):
        r = g.submit(ch, d)
        if isinstance(r, dict) and (r.get("result") or r.get("flag")):
            return r
        time.sleep(2 + 2 * t)
    return r


if mode == "bank":
    inc = sys.argv[4]; exc = sys.argv[5] if len(sys.argv) > 5 else None
    d = {k: v for k, v in ans.items() if re.search(inc, k) and not (exc and re.search(exc, k))}
    r = sub(d)
    print("BANK", len(d), sorted(d)[:3], "->", r.get("result"), r.get("remaining"), r.get("flag"))
elif mode == "try":
    aid = sys.argv[4]
    for c in sys.argv[5:]:
        r = sub({aid: c})
        print("TRY", aid, repr(c), "->", r.get("result"), r.get("remaining"), r.get("flag"), flush=True)
        if r.get("result") in ("accepted", "CORRECT") or r.get("flag"):
            break
        time.sleep(1.6)
