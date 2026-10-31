import sys, json
sys.path.insert(0, "~/ctf")
from gm import GM
g = GM()
for ch in sys.argv[1:]:
    s = g.status(ch)
    s.pop("questions", None); s.pop("guidance", None); s.pop("answer_ids", None)
    print(ch, json.dumps(s)[:1500])
