#!/usr/bin/env python3
import sys, re, json, io, time, struct
sys.path.insert(0, '/home/HuntressCTF/codex_day4_bin')
import d4b_solve as M
import requests, pyzipper
S = M.S; GM = M.GM; BASE = M.BASE; WORK = M.WORK

def files_from(cid, delivery, tag):
    params = {"op": "artifact", "challenge": cid}
    if delivery is not None: params["delivery"] = delivery
    raw = S.get(GM, params=params).content
    if raw[:2] != b"PK": return None
    z = pyzipper.AESZipFile(io.BytesIO(raw)); z.setpassword(b"infected")
    out = {}
    for n in z.namelist():
        if n.endswith("/"): continue
        bn = n.split("/")[-1]; p = f"{WORK}/{tag}_{bn}"; data = z.read(n)
        open(p, "wb").write(data); out[bn] = (p, data)
    return out

def build_cand(files):
    def g(pat):
        for n in files:
            if re.match(pat, n, re.I): return files[n]
        return (None, None)
    d01p, d01b = g(r"d01-.*\.elf$")
    d02p, d02b = g(r"d02-.*\.elf$")
    d03p, d03b = g(r"d03-.*\.dll$")
    rcp, rcb = g(r"d03-.*runtimeconfig.*")
    d04p, d04b = g(r"d04-.*\.elf$")
    C = {}
    if d01b is not None: C.update(M.d01_fields(d01p, d01b, "d01_"))
    if d02b is not None:
        C.update(M.cfg_fields(d02b, "d02_", True, True)); C["d02_analysis_format"] = ["elf"]
    if d03b is not None:
        pos = d03b.index(b"BSJB"); ln = int.from_bytes(d03b[pos+12:pos+16], "little")
        C.update(M.cfg_fields(d03b, "d03_", False, False))
        C["d03_artifact_sha256_1"] = [M.h(d03b), M.h(rcb)]; C["d03_artifact_sha256_2"] = [M.h(rcb), M.h(d03b)]
        C["d03_analysis_format"] = ["pe_cli"]; C["d03_analysis_machine"] = ["i386"]
        C["d03_analysis_metadata_version"] = [d03b[pos+16:pos+16+ln].rstrip(b"\x00").decode()]
    if d04b is not None:
        C.update(M.cfg_fields(d04b, "d04_", True, False))
        C["d04_analysis_architecture"] = ["x86-64", "amd64"]; C["d04_analysis_format"] = ["elf"]
    return C

def submit(cid, ans):
    for _ in range(3):
        r = S.post(GM, data=json.dumps({"op": "submit", "challenge": cid, "answers": ans})).json()
        if r.get("error") == "rate_limited": time.sleep(1.0); continue
        return r
    return r

def solve(mode, tries=6):
    cid = BASE + ("/" + mode if mode != "single_solve" else "")
    for whole in range(tries):
        t = time.time()
        time.sleep(2.0)
        r = S.post(GM, data=json.dumps({"op": "start" if whole == 0 else "retry", "challenge": cid})).json()
        if r.get("error") == "rate_limited": time.sleep(4); r = S.post(GM, data=json.dumps({"op": "start", "challenge": cid})).json()
        if "answer_ids" not in r: r = S.post(GM, data=json.dumps({"op": "start", "challenge": cid})).json()
        if "answer_ids" not in r:
            print(mode, "start:", {k: r.get(k) for k in ("error", "result")}); time.sleep(3); continue
        ids = r["answer_ids"]
        sets = sorted({int(m[1]) for x in ids if (m := re.match(r"set(\d+)\.", x))})
        CAND = {}
        if sets:
            for sn in sets:
                fs = files_from(cid, sn-1, f"s{sn}") or files_from(cid, None, f"s{sn}")
                if fs:
                    for k, v in build_cand(fs).items(): CAND[f"set{sn}.{k}"] = v
        else:
            fs = files_from(cid, None, "tt")
            CAND = build_cand(fs) if fs else {}
        ans = {i: CAND[i][0] for i in ids if i in CAND and CAND[i] and CAND[i][0] is not None}
        r1 = submit(cid, ans)
        print(mode, "whole", whole, "ids", len(ids), "computed", len(ans),
              {k: r1.get(k) for k in ("result", "remaining", "flag", "error")}, "el", round(time.time()-t, 2), flush=True)
        if r1.get("result") == "CORRECT":
            print(mode, "SOLVED", r1.get("flag")); return r1.get("flag")
        # banking fallback: bank confident, then brute-force multi-candidate fields
        base = {i: CAND[i][0] for i in ids if i in CAND and len(CAND[i]) == 1 and CAND[i][0] is not None}
        rb = submit(cid, base)
        if rb.get("result") in ("accepted", "CORRECT"):
            if rb.get("result") == "CORRECT": print(mode, "SOLVED", rb.get("flag")); return rb.get("flag")
            for i in ids:
                if i in base: continue
                for c in CAND.get(i, []):
                    if c is None: continue
                    rr = submit(cid, {**base, i: c})
                    if rr.get("result") == "CORRECT": print(mode, "SOLVED", rr.get("flag")); return rr.get("flag")
                    if rr.get("result") == "accepted": base[i] = c; break
        time.sleep(1.0)
    print(mode, "UNSOLVED"); return None

if __name__ == "__main__":
    for m in sys.argv[1:]:
        solve(m)
