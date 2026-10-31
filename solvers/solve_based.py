#!/usr/bin/env python3
"""Generic solver for the 'A Little Based' family (Base64 blob -> final-line slug).

Usage: solve_based.py <challenge-id>

Flow: start -> for each question fetch its assigned blob bytes -> fully base64-
decode (through nested layers if present) -> extract the answer slug from the
final non-empty decoded line -> submit all answers in one request. Reads only
genuine Game Master responses and the downloaded bytes; never hand-types them.
"""
import sys, re, json, base64, hashlib, io, zipfile, datetime
import requests

GM = "http://<homebase-ip>/huntress-ctf-proxy"
S = requests.Session()
S.headers.update({"Content-Type": "application/json"})

# answer slug: three lowercase words + two-digit number, e.g. dashing-tent-mosaic-17
SLUG = re.compile(r"[a-z]+-[a-z]+-[a-z]+-\d{2}")
B64CHARS = re.compile(r"^[A-Za-z0-9+/=\s]+$")


def cap_from_path(p):
    if not p:
        return None
    m = re.search(r"([0-9a-f]{64})", p)
    return m.group(1) if m else None


def fetch_artifact(challenge, capability=None, delivery=None):
    params = {"op": "artifact", "challenge": challenge}
    if capability:
        params["capability"] = capability
    if delivery is not None:
        params["delivery"] = delivery
    r = S.get(GM, params=params, timeout=20)
    return r.content


def looks_b64(s):
    t = s.strip()
    if len(t) < 8 or len(t.replace("\n", "").replace("\r", "")) % 4 != 0:
        return False
    return bool(B64CHARS.match(t))


def decode_completely(raw):
    """Repeatedly base64-decode while the payload still looks like base64.
    Returns the final decoded text (utf-8, errors replaced)."""
    try:
        cur = raw.decode("utf-8", "replace")
    except Exception:
        cur = str(raw)
    layers = []
    for _ in range(12):  # guard against loops
        layers.append(cur)
        if not looks_b64(cur):
            break
        try:
            dec = base64.b64decode(cur.strip(), validate=False)
            txt = dec.decode("utf-8", "replace")
        except Exception:
            break
        # stop if decoding produced mostly non-printable garbage
        printable = sum(c.isprintable() or c in "\n\r\t " for c in txt)
        if not txt or printable / max(len(txt), 1) < 0.85:
            break
        cur = txt
        if SLUG.search(cur):  # found the slug -> no need to keep peeling
            break
    return cur, layers


def final_nonempty_line(text):
    lines = [ln for ln in text.splitlines() if ln.strip()]
    return lines[-1] if lines else text.strip()


INDEX_PREFIX = re.compile(r"^\s*\d+[\t ]+(.*)$")  # e.g. "01\t<base64>"


def strip_index(line):
    m = INDEX_PREFIX.match(line)
    return m.group(1) if m else line


def solve_blob(raw):
    """From assigned blob bytes, return (slug, final_decoded_line, layers).
    Handles an optional 'NN\\t' index prefix on the final line, then fully
    base64-decodes the payload."""
    text = raw.decode("utf-8", "replace")
    payload = strip_index(final_nonempty_line(text))
    decoded, layers = decode_completely(payload.encode("utf-8", "replace"))
    slug, last = extract_slug(decoded)
    return slug, last, layers


def extract_slug(text):
    last = final_nonempty_line(text)
    m = SLUG.search(last)
    if m:
        return m.group(0), last
    m = SLUG.search(text)  # fallback: anywhere
    return (m.group(0) if m else None), last


def deadline_future(deadline):
    if not deadline:
        return True
    try:
        dl = datetime.datetime.fromisoformat(deadline.replace("Z", "+00:00"))
        return dl > datetime.datetime.now(datetime.timezone.utc)
    except Exception:
        return True


def get_attempt_state(challenge):
    """Start (or resume) the attempt; renew with retry if the timer is expired."""
    st = S.post(GM, data=json.dumps({"challenge": challenge})).json()
    if st.get("error") or not deadline_future(st.get("deadline")):
        rt = S.post(GM, data=json.dumps({"op": "retry", "challenge": challenge})).json()
        if not rt.get("error"):
            st = rt
    return st


def main():
    challenge = sys.argv[1]
    print(f"### challenge: {challenge}")

    start = get_attempt_state(challenge)
    mode = start.get("mode")
    deadline = start.get("deadline")
    questions = start.get("questions") or []
    answer_ids = start.get("answer_ids") or [q.get("id") for q in questions]
    print(f"mode={mode} deadline={deadline} answer_ids={answer_ids} questions={len(questions)}")

    # One default fetch; if it's a zip bundle, map members by filename.
    default_raw = fetch_artifact(challenge)
    members = {}
    if default_raw[:2] == b"PK":
        try:
            zf = zipfile.ZipFile(io.BytesIO(default_raw))
            for n in zf.namelist():
                members[n] = zf.read(n)
            print(f"bundle: zip with {len(members)} members: {list(members)}")
        except Exception as e:
            print(f"zip parse failed: {e}")

    answers = {}
    for i, q in enumerate(questions):
        qid = q.get("id", answer_ids[i] if i < len(answer_ids) else str(i))
        art = q.get("artifact")
        if members:                      # bundle: pick this question's member
            raw = members.get(art) or members.get(art and art.split("/")[-1], b"")
        elif len(questions) == 1:        # single blob delivered directly
            raw = default_raw
        else:                            # multiple separate deliveries
            cap = cap_from_path(q.get("download")) or q.get("capability")
            raw = fetch_artifact(challenge, capability=cap, delivery=q.get("delivery", i))
        sha = hashlib.sha256(raw).hexdigest()
        slug, last, layers = solve_blob(raw)
        print(f"- q[{i}] id={qid} artifact={art} bytes={len(raw)} sha256={sha}")
        print(f"    decoded_final_line: {last!r}")
        print(f"    slug: {slug}")
        answers[qid] = slug

    print(f"### submitting: {answers}")
    res = S.post(GM, data=json.dumps({"challenge": challenge, "answers": answers})).json()
    print("### RESULT:")
    print(json.dumps({k: res.get(k) for k in ("result", "flag", "status", "remaining", "name", "accepted", "message")}, indent=2))
    print("### RAW:", json.dumps(res)[:800])


if __name__ == "__main__":
    main()
