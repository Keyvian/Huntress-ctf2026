#!/usr/bin/env python3
"""Solver for the metadata-forensics 'hash-to-ride' family.

Builds an identity inventory from real bytes. Because the mastery packaging
varies per attempt (outer zip of inner zips, or files spread across deliveries,
with intentionally untrustworthy labels), everything is done in ONE process and
ONE attempt: start, then gather EVERY reachable file (default artifact + each
valid delivery, recursing through nested zips), then map each question to its
target file by basename hint (falling back to content) and report filename /
size / MD5 / SHA-1 / SHA-256. Never reuses bytes across attempts."""
import sys, json, io, zipfile, hashlib
import requests

GM = "http://<homebase-ip>/huntress-ctf-proxy"
S = requests.Session(); S.headers.update({"Content-Type": "application/json"})
NOTE_SIGS = (b"Metadata Forensics", b"Case marker", b"Analyst", b"Endpoint", b"Huntress CTF")
PROP_SUFFIXES = ["filename", "size-bytes", "md5", "sha1", "sha256", "sha512"]


def start_attempt(cid):
    st = S.post(GM, data=json.dumps({"op": "start", "challenge": cid})).json()
    if st.get("answer_ids") is None or st.get("error"):
        rt = S.post(GM, data=json.dumps({"op": "retry", "challenge": cid})).json()
        if rt.get("answer_ids"):
            st = rt
    return st


def fetch(cid, delivery=None):
    p = {"op": "artifact", "challenge": cid}
    if delivery is not None:
        p["delivery"] = delivery
    return S.get(GM, params=p).content


def is_error_blob(b):
    return b[:1] == b"{" and b"error" in b[:60]


def extract_all(blob, prefix, out):
    """Recurse through zips, collecting leaf files as {full_path: bytes}."""
    if blob[:2] != b"PK":
        return
    try:
        z = zipfile.ZipFile(io.BytesIO(blob))
    except Exception:
        return
    for info in z.infolist():
        try:
            b = z.read(info.filename)
        except Exception:
            continue
        path = prefix + info.filename
        if info.filename.lower().endswith(".zip") and b[:2] == b"PK":
            extract_all(b, path + " -> ", out)
        else:
            out[path] = b


def gather_files(cid):
    out = {}
    blobs = [fetch(cid)]
    for i in range(0, 10):
        d = fetch(cid, delivery=i)
        if d and not is_error_blob(d):
            blobs.append(d)
    for b in blobs:
        if b[:2] == b"PK":
            extract_all(b, "", out)
        elif b and not is_error_blob(b):
            out.setdefault("__raw_%d" % len(out), b)
    return out


def digests(b):
    return {
        "size-bytes": str(len(b)),
        "md5": hashlib.md5(b).hexdigest(),
        "sha1": hashlib.sha1(b).hexdigest(),
        "sha256": hashlib.sha256(b).hexdigest(),
        "sha512": hashlib.sha512(b).hexdigest(),
    }


def classify(qid):
    for suf in PROP_SUFFIXES:
        if qid.endswith("-" + suf):
            return suf
    return None


def group_base(qid, prop):
    return qid[: -(len(prop) + 1)] if prop and qid.endswith("-" + prop) else qid


def parse_artifact(art):
    if not art:
        return None, None
    if "->" in art:
        left, right = art.rsplit("->", 1)
        return left.strip(), right.strip().split("/")[-1]
    return art.strip(), None


def basename(p):
    return p.split(" -> ")[-1].split("/")[-1]


def resolve(files, hint, kind):
    """Return the full path key of the target file."""
    if not files:
        return None
    # 1) exact basename == hint
    if hint:
        exact = [p for p in files if basename(p) == hint]
        if len(exact) == 1:
            return exact[0]
        if len(exact) > 1:
            return exact[0]
    # 2) content: evidence notes carry the template signature
    notes = [p for p in files if any(s in files[p][:400] for s in NOTE_SIGS)]
    low = (kind or "").lower()
    if "roster" in low:
        csv = [p for p in files if files[p][:200].lower().startswith(b"case_marker")
               or b"endpoint_id" in files[p][:200]]
        if csv:
            return csv[0]
    if notes:
        if "copy" in low:
            renamed = [p for p in notes if basename(p) != "evidence-note.txt"]
            return (renamed or notes)[0]
        canonical = [p for p in notes if basename(p) == "evidence-note.txt"]
        return (canonical or notes)[0]
    if len(files) == 1:
        return list(files)[0]
    return None


def main():
    cid = sys.argv[1]
    dry = "dry" in sys.argv[2:]
    print("### challenge:", cid)
    st = start_attempt(cid)
    qs = st.get("questions") or []
    print("mode=%s deadline=%s questions=%d" % (st.get("mode"), st.get("deadline"), len(qs)))

    files = gather_files(cid)
    print("### gathered files (%d):" % len(files))
    for p, b in files.items():
        print("   %r  bytes=%d  note_sig=%s" % (p, len(b), any(s in b[:400] for s in NOTE_SIGS)))

    groups = {}
    for q in qs:
        qid = q["id"]; prop = classify(qid); base = group_base(qid, prop)
        g = groups.setdefault(base, {"qs": [], "arts": []})
        g["qs"].append((qid, prop)); g["arts"].append(q.get("artifact"))

    answers = {}
    for base, g in groups.items():
        hint = None
        for art in g["arts"]:
            _, h = parse_artifact(art)
            hint = hint or h
        target = resolve(files, hint, base)
        tb = files.get(target, b"")
        d = digests(tb); d["filename"] = basename(target) if target else None
        print("- group=%s hint=%s -> target=%r bytes=%d md5=%s" % (base, hint, target, len(tb), d["md5"]))
        for qid, prop in g["qs"]:
            answers[qid] = d.get(prop)

    print("### submitting:", json.dumps(answers, indent=2))
    if dry:
        print("### DRY RUN — not submitting"); return
    res = S.post(GM, data=json.dumps({"op": "submit", "challenge": cid, "answers": answers})).json()
    print("### RESULT:", json.dumps({k: res.get(k) for k in
          ("result", "flag", "status", "remaining", "accepted", "message", "error")}, indent=2))


if __name__ == "__main__":
    main()
