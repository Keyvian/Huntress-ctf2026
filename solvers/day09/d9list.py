import sys, re, json
sys.path.insert(0, "~/ctf")
from gm import GM
g = GM()
day = sys.argv[1] if len(sys.argv) > 1 else "9"
j = g.get("?op=list&day=%s" % day).json()
print("MSG", j.get("message"))
for c in j.get("challenges", []):
    print(c.get("id"), "|", c.get("mode"), "|", c.get("lane"), "|", c.get("name"), "| solved=", c.get("solved"), "|", (c.get("solved_by") or {}).get("at"))
    print("   prompt:", c.get("prompt"))
if len(sys.argv) > 2:
    c = j["challenges"][int(sys.argv[2])]
    print(json.dumps(c, indent=1, ensure_ascii=False))
