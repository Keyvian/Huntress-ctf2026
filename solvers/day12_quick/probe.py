"""Day-11 quick-group probe: print the list entry + status contract for each assigned challenge.
Gentle pacing with backoff on rate_limited (3 parallel agents share the token)."""
import sys, json, time
sys.path.insert(0, "~/ctf")
from gm import GM

g = GM()


def call(fn, *a):
    d = 2.0
    for _ in range(8):
        r = fn(*a)
        if isinstance(r, dict) and r.get("error") == "rate_limited":
            time.sleep(d); d *= 1.6; continue
        return r
    return r


IDS = sys.argv[1:]
lst = call(lambda: g.get("?op=list&day=12").json())
items = lst if isinstance(lst, list) else (lst.get("challenges") or lst.get("items") or [lst])
for it in items:
    cid = it.get("id") or it.get("challenge") or ""
    if any(cid.startswith(i) for i in IDS):
        print(json.dumps({k: v for k, v in it.items() if k not in ("guidance",)})[:1500])
for i in IDS:
    time.sleep(1.5)
    st = call(g.status, i)
    print("=== STATUS", i)
    print(json.dumps({k: v for k, v in st.items() if k != "guidance"}, indent=1)[:6000])
