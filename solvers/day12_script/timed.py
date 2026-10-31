"""One-process timed runner for the Day-10 script lane (Bind Over Matter).
usage: timed.py <challenge> <outdir> [--dry]
start -> fetch default artifact (+ deliveries for missing sets) -> compute (s9/sdec static decode) -> full submit;
if the full submit is incorrect, bank per-file groups in parallel and report the wrong groups."""
import sys, os, re, json, time, io
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, "~/ctf")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gm import GM
import pyzipper
from s9 import load, compute

T0 = time.time()
def el(): return "%.2fs" % (time.time() - T0)

ch, dd = sys.argv[1], sys.argv[2]
dry = "--dry" in sys.argv
os.makedirs(dd, exist_ok=True)
for f in os.listdir(dd):
    if f.startswith("artifact") and f.endswith(".bin"):
        os.remove(os.path.join(dd, f))
g = GM()


def call(fn, *a):
    # 3 parallel agents share one GM token -> back off on rate_limited
    r = None
    for i in range(10):
        r = fn(*a)
        if isinstance(r, dict) and r.get("error") == "rate_limited":
            time.sleep(min(1.0 * 1.6 ** i, 8)); continue
        if isinstance(r, bytes) and b"rate_limited" in r[:60]:
            time.sleep(min(0.5 * 1.6 ** i, 4)); continue
        return r
    return r


st = call(g.start, ch)
if st.get("error"):
    print("START ERROR", st.get("error"), json.dumps(st)[:400]); sys.exit(1)
json.dump(st, open(os.path.join(dd, "start.json"), "w"))
qs = st["questions"]
nsets = max([int(m.group(1)) for q in qs for m in [re.match(r"set(\d+)\.", q["id"])] if m] or [1])
print(el(), "mode", st.get("mode"), "deadline", st.get("deadline"), "started", st.get("started_at"), "nq", len(qs), "sets", nsets, flush=True)
b = call(g.artifact, ch)
open(os.path.join(dd, "artifact.bin"), "wb").write(b)
print(el(), "artifact", len(b), flush=True)
_, sets = load(dd)
if len(sets) < nsets:
    def fd(k):
        return k, call(g.artifact, ch, k)
    with ThreadPoolExecutor(6) as ex:
        for k, bb in ex.map(fd, range(1, nsets)):
            if bb[:1] != b"{":
                open(os.path.join(dd, "artifact_d%d.bin" % k), "wb").write(bb)
            else:
                print("delivery", k, bb[:80])
    st2, sets = load(dd)
print(el(), "sets loaded", sorted(sets), flush=True)
ans, diag = compute(st, sets)
aids = st.get("answer_ids") or [q["id"] for q in qs]
print(el(), "computed", len(ans), "/", len(aids), "diag", diag[:10], flush=True)
json.dump(ans, open(os.path.join(dd, "answers.json"), "w"), indent=0)
if dry:
    sys.exit(0)

def send(sub, tries=6):
    r = None
    for t in range(tries):
        try:
            r = GM().submit(ch, sub)
        except Exception as e:
            r = {"exc": repr(e)}
        if isinstance(r, dict) and (r.get("result") or r.get("flag")):
            return r
        time.sleep(0.5 + 0.7 * t)
    return r or {}

full = {k: ans[k] for k in aids if k in ans}
r = send(full)
print(el(), "FULL SUBMIT ->", r.get("result"), "rem", r.get("remaining"), "flag", r.get("flag"), "err", r.get("error"), flush=True)
if r.get("flag") or r.get("result") in ("CORRECT", "already_solved"):
    sys.exit(0)
# fallback: bank per artifact-file groups in parallel
art = {q["id"]: q.get("artifact", "") for q in qs}
groups = {}
for a in full:
    sk = a.split(".")[0] + ":" if a.startswith("set") else ""
    groups.setdefault(sk + art[a], []).append(a)
bad, flag = [], None
def one(gk):
    return gk, send({k: full[k] for k in groups[gk]})
with ThreadPoolExecutor(5) as ex:
    for gk, rr in ex.map(one, list(groups)):
        if rr.get("flag"):
            flag = rr["flag"]
        if rr.get("result") == "incorrect":
            bad.append(gk)
        elif not rr.get("result"):
            bad.append(gk + " [NORESP %s]" % json.dumps(rr)[:80])
print(el(), "BAD_GROUPS", bad, "FLAG", flag, flush=True)
json.dump(bad, open(os.path.join(dd, "bad.json"), "w"))
