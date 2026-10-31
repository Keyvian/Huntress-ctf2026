#!/usr/bin/env python3
import sys, re, json, io, zipfile, time, struct
import requests
GM = "http://<homebase-ip>/huntress-ctf-proxy"
S = requests.Session(); S.headers.update({"Content-Type": "application/json"})
BASE = "metadata-forensics-day-04-picture-this"

def sof(data):
    i, n = 2, len(data)
    if data[:2] != b"\xff\xd8": return None
    while i + 1 < n:
        if data[i] != 0xFF: i += 1; continue
        m = data[i+1]
        if m == 0xD8 or m == 0xD9 or 0xD0 <= m <= 0xD7 or m == 0x01 or m == 0xFF: i += 2 if m != 0xFF else 1; continue
        if i + 4 > n: break
        ln = struct.unpack(">H", data[i+2:i+4])[0]
        if 0xC0 <= m <= 0xCF and m not in (0xC4, 0xC8, 0xCC):
            h = struct.unpack(">H", data[i+5:i+7])[0]; w = struct.unpack(">H", data[i+7:i+9])[0]
            return w, h
        i += 2 + ln
    return None

def extract(b, out, pfx=""):
    if b[:2] != b"PK": return
    try: z = zipfile.ZipFile(io.BytesIO(b))
    except: return
    for nnn in z.namelist():
        d = z.read(nnn)
        if nnn.lower().endswith(".zip") and d[:2] == b"PK": extract(d, out, pfx)
        elif not nnn.endswith("/"): out[nnn.split("/")[-1]] = d

def get(cid, delivery=None):
    p = {"op": "artifact", "challenge": cid}
    if delivery is not None: p["delivery"] = delivery
    for _ in range(6):
        r = S.get(GM, params=p)
        if r.content[:1] == b"{" and b"rate_limited" in r.content: time.sleep(2); continue
        return r.content
    return r.content

def submit(cid, a):
    for _ in range(6):
        r = S.post(GM, data=json.dumps({"op": "submit", "challenge": cid, "answers": a})).json()
        if r.get("error") == "rate_limited": time.sleep(2); continue
        return r
    return r

def answer_for(data):
    r = sof(data)
    return f"{r[0]}x{r[1]}" if r else "none"

def solve(mode, tries=8):
    cid = BASE + ("/" + mode if mode != "single_solve" else "")
    for whole in range(tries):
        r = S.post(GM, data=json.dumps({"op": "start" if whole == 0 else "retry", "challenge": cid})).json()
        if "answer_ids" not in r:
            r = S.post(GM, data=json.dumps({"op": "start", "challenge": cid})).json()
        if "answer_ids" not in r:
            if r.get("error") == "prerequisite_required": return ("LOCKED", None)
            time.sleep(1.5); continue
        qs = r.get("questions") or []; ids = r.get("answer_ids") or []
        files = {}
        extract(get(cid), files)
        nsets = len({q.get("set") for q in qs if q.get("set")})
        if len(files) < max(1, nsets):
            for i in range(max(1, nsets)):
                extract(get(cid, i), files)
        names = sorted(files)
        ans = {}
        for q in qs:
            art = q.get("artifact") or ""; hint = art.split("->")[-1].strip().split("/")[-1]
            f = files.get(hint)
            if f is None:
                jn = [n for n in names if n.lower().endswith((".jpg", ".jpeg"))]
                sn = q.get("set")
                if sn and 1 <= sn <= len(jn): f = files[jn[sn-1]]
                elif len(jn) == 1: f = files[jn[0]]
            ans[q["id"]] = answer_for(f) if f is not None else "none"
        res = submit(cid, ans)
        print(mode, "whole", whole, "ids", len(ids), "files", len(files),
              {k: res.get(k) for k in ("result", "remaining", "flag", "error")}, flush=True)
        if res.get("result") == "CORRECT": return ("CORRECT", res.get("flag"))
        time.sleep(1.5)
    return ("UNSOLVED", None)

if __name__ == "__main__":
    for mode in sys.argv[1:] or ["time_trial", "mastery"]:
        print("=>", mode, solve(mode))
