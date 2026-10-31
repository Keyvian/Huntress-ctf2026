#!/usr/bin/env python3
import re, base64, binascii, codecs
WORDS = ["nice", "work", "decod", "warmup", "solve", "submit", "exact", "answer",
         "game", "master", "this", " the ", " to ", "congrat"]
SLUG = re.compile(r"[a-z]+-[a-z]+-[a-z]+-\d{2}")

def line_cands(p):
    out = [p]
    try: out.append(codecs.decode(p, "rot_13"))
    except: pass
    try:
        d = base64.b64decode(p + "===", validate=False).decode("utf-8", "replace")
        if d: out.append(d)
    except: pass
    try: out.append(binascii.unhexlify(re.sub(r"\s", "", p)).decode("utf-8", "replace"))
    except: pass
    try: out.append(base64.b32decode(p + "=" * ((8 - len(p) % 8) % 8)).decode("utf-8", "replace"))
    except: pass
    bits = re.sub(r"[^01]", "", p)
    if re.fullmatch(r"[01\s]+", p or "") and bits and len(bits) % 8 == 0:
        try: out.append(bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8)).decode("utf-8", "replace"))
        except: pass
    return out

def score(t):
    low = t.lower()
    s = sum(10 for w in WORDS if w in low)
    if SLUG.search(low): s += 12
    printable = sum(1 for c in t if 32 <= ord(c) < 127)
    s += printable / max(len(t), 1) * 2
    return s

def reconstruct(raw):
    text = raw.decode("utf-8", "replace")
    lines = [l for l in text.splitlines() if l.strip()]
    pieces = []
    for l in lines:
        m = re.match(r"^\s*\d+[ \t]+(.*)$", l)
        payload = m.group(1) if m else l
        best = max(line_cands(payload), key=score)
        pieces.append(best)
    full = "".join(pieces)
    mm = re.search(r"[Mm]aster[:\s]+([a-z]+-[a-z]+-[a-z]+-\d{2})", full) or SLUG.search(full)
    return full, (mm.group(1) if mm and mm.groups() else (mm.group(0) if mm else None))

if __name__ == "__main__":
    import requests, json, sys
    GM = "http://<homebase-ip>/huntress-ctf-proxy"
    S = requests.Session(); S.headers.update({"Content-Type": "application/json"})
    C = "warmups-day-04/mastery"
    S.post(GM, data=json.dumps({"op": "start", "challenge": C}))
    raw = S.get(GM, params={"op": "artifact", "challenge": C, "delivery": 0}).content
    full, slug = reconstruct(raw)
    print("reconstructed:", repr(full))
    print("slug:", slug)
