#!/usr/bin/env python3
import sys, re, json, time
sys.path.insert(0, '/home/HuntressCTF/codex_day4_bin')
import d4b_timed as T
S, GM, BASE = T.S, T.GM, T.BASE

def gather_cand(cid, ids, sets):
    """Build CAND with full coverage, pulling from default + deliveries as needed."""
    CAND = {}
    if sets:
        for sn in sets:
            fs = T.files_from(cid, sn-1, f"f{sn}") or T.files_from(cid, None, f"f{sn}")
            if fs:
                for k, v in T.build_cand(fs).items(): CAND[f"set{sn}.{k}"] = v
    else:
        fs = T.files_from(cid, None, "f0")
        if fs: CAND = T.build_cand(fs)
    return CAND

def full(ids, CAND):
    return all(i in CAND and CAND[i] and CAND[i][0] is not None for i in ids)

def solve(mode, tries=12):
    cid = BASE + ("/" + mode if mode != "single_solve" else "")
    for whole in range(tries):
        time.sleep(3)
        r = S.post(GM, data=json.dumps({"op": "start" if whole == 0 else "retry", "challenge": cid})).json()
        if r.get("error") == "rate_limited": time.sleep(5); continue
        if "answer_ids" not in r:
            r = S.post(GM, data=json.dumps({"op": "start", "challenge": cid})).json()
        if "answer_ids" not in r:
            print(mode, whole, "start", {k: r.get(k) for k in ("error", "result")}); continue
        t = time.time()
        ids = r["answer_ids"]
        sets = sorted({int(m[1]) for x in ids if (m := re.match(r"set(\d+)\.", x))})
        CAND = gather_cand(cid, ids, sets)
        cov = sum(1 for i in ids if i in CAND and CAND[i] and CAND[i][0] is not None)
        if not full(ids, CAND):
            print(mode, whole, "partial coverage", cov, "/", len(ids), "- retry", flush=True); continue
        ans = {i: CAND[i][0] for i in ids}
        res = S.post(GM, data=json.dumps({"op": "submit", "challenge": cid, "answers": ans})).json()
        print(mode, whole, "submit", len(ans), {k: res.get(k) for k in ("result", "remaining", "flag", "error")}, "el", round(time.time()-t, 2), flush=True)
        if res.get("result") == "CORRECT":
            print(mode, "SOLVED", res.get("flag")); return res.get("flag")
        if res.get("error") == "rate_limited": time.sleep(5)
    print(mode, "UNSOLVED"); return None

if __name__ == "__main__":
    for m in sys.argv[1:]:
        solve(m)
