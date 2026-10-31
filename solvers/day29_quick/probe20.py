"""Probe the naming convention of a single-answer untimed attempt: submit each candidate in turn until CORRECT/accepted.
usage: probe20.py <challenge> <answer_id> <candidate-json-string>..."""
import sys, os, time, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gmx import GMX

ch, aid = sys.argv[1], sys.argv[2]
g = GMX()
st = g.post({"op": "start", "challenge": ch})
print("mode", st.get("mode"), "deadline", st.get("deadline"), "ids", st.get("answer_ids"))
for cand in sys.argv[3:]:
    r = g.submit(ch, {aid: cand})
    print("%-40s -> %s" % (cand, {k: r.get(k) for k in ("result", "flag", "error", "remaining")}))
    if r.get("result") in ("CORRECT", "accepted") or r.get("flag"):
        print("WINNER", cand); break
    time.sleep(1.6)
