#!/usr/bin/env python3
import sys, re, json, io, zipfile, codecs, base64, binascii, time
import requests
GM = "http://<homebase-ip>/huntress-ctf-proxy"
S = requests.Session(); S.headers.update({"Content-Type": "application/json"})
C = sys.argv[1] if len(sys.argv) > 1 else "warmups-day-04/mastery"

def unpk(b):
    if b[:2] != b"PK": return None
    try:
        z = zipfile.ZipFile(io.BytesIO(b))
        for n in z.namelist():
            if not n.endswith("/"): return z.read(n)
    except: return None
    return None

def transforms(s):
    yield s
    try: yield codecs.decode(s, "rot_13")
    except: pass
    try:
        d = base64.b64decode(s + "===", validate=False).decode("utf-8", "replace")
        if d: yield d
    except: pass
    try: yield base64.b32decode(s + "=" * ((8 - len(s) % 8) % 8)).decode("utf-8", "replace")
    except: pass
    try: yield binascii.unhexlify(re.sub(r"\s", "", s)).decode("utf-8", "replace")
    except: pass
    bits = re.sub(r"[^01]", "", s)
    if re.fullmatch(r"[01\s]+", s or "") and bits and len(bits) % 8 == 0:
        try: yield bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8)).decode("utf-8", "replace")
        except: pass

def plain_slug(raw):
    if raw is None: return None
    text = raw.decode("utf-8", "replace")
    body = re.sub(r"^\s*\d+[ \t]+", "", text, count=1)   # drop leading NN<tab> index
    nolf = body.replace("\n", "").replace("\r", "")       # join wrapped lines
    frontier = [nolf, body, text]
    seen = set()
    for _ in range(5):
        nxt = []
        for s in frontier:
            for t in transforms(s):
                if t in seen: continue
                seen.add(t)
                if "Game Master" in t:
                    mm = re.search(r"Master[:\s]+([a-z]+-[a-z]+-[a-z]+-\d{2})", t)
                    if mm: return mm.group(1)
                nxt.append(t)
        frontier = nxt
    return None

def get(params):
    for _ in range(6):
        r = S.get(GM, params=params)
        if r.content[:1] == b"{" and b"rate_limited" in r.content: time.sleep(2.0); continue
        return r.content
    return r.content

def submit(ans):
    for _ in range(6):
        r = S.post(GM, data=json.dumps({"op": "submit", "challenge": C, "answers": ans})).json()
        if r.get("error") == "rate_limited": time.sleep(2.0); continue
        return r
    return r

for whole in range(5):
    r = S.post(GM, data=json.dumps({"op": "start" if whole == 0 else "retry", "challenge": C})).json()
    if "answer_ids" not in r:
        r = S.post(GM, data=json.dumps({"op": "start", "challenge": C})).json()
    qs = r.get("questions") or []; ids = r.get("answer_ids") or []
    ans = {}
    for q in qs:
        sn = q.get("set")
        raw = get({"op": "artifact", "challenge": C, "delivery": sn - 1})
        ans[q["id"]] = plain_slug(unpk(raw) or raw)
    miss = [k for k, v in ans.items() if not v]
    print("whole", whole, "ids", len(ids), "decoded", len(ans) - len(miss), "missing", miss[:6], flush=True)
    if miss: time.sleep(1.5); continue
    res = submit(ans)
    print("  RESULT", {k: res.get(k) for k in ("result", "remaining", "flag", "error")}, flush=True)
    if res.get("result") == "CORRECT": print("SOLVED", res.get("flag")); break
    time.sleep(1.5)
