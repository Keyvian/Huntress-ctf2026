"""Day-16 metadata 'Return to Sender' solver (any mode) = m15 (+ all prior-day fields) + email.<field> for .eml artifacts.
email.<snake>: RFC 5322 header value verbatim (unfolded), e.g. message_id -> Message-ID (<...> kept, graded CORRECT day-16
single_solve), in_reply_to, references, subject, from, to, date, x_huntress_correlation; derived: attachment_filenames,
attachment_count, attachment_sha256/md5/size_bytes (first attachment, decoded), body_text, correlation_token.
json-kind answers whose value is not JSON are split on whitespace into a compact JSON array (e.g. references).
usage: m16.py <challenge> [start|retry|practice|none] [--submit] [--dir cached] [--save outdir]"""
import sys, os, re, json, time, hashlib, email, email.policy
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import m15
from m15 import unzip_all, solve, map_ids, cj

_ECACHE = {}


def email_msg(b):
    k = hashlib.sha1(b).digest()
    if k not in _ECACHE:
        _ECACHE[k] = email.message_from_bytes(b, policy=email.policy.compat32)
    return _ECACHE[k]


EMAIL_ALIASES = {"message_id": "Message-ID", "messageid": "Message-ID", "in_reply_to": "In-Reply-To", "references": "References",
                 "subject": "Subject", "from": "From", "sender": "From", "from_address": "From", "to": "To", "cc": "Cc",
                 "bcc": "Bcc", "date": "Date", "reply_to": "Reply-To", "return_path": "Return-Path",
                 "correlation": "X-Huntress-Correlation", "correlation_header": "X-Huntress-Correlation",
                 "mime_version": "MIME-Version", "content_type": "Content-Type", "boundary": "__boundary"}


def unfold(v):
    return re.sub(r"\s*\r?\n\s*", " ", str(v)).strip()


def attachments(m):
    out = []
    for part in m.walk():
        if part.is_multipart():
            continue
        cd = str(part.get("Content-Disposition") or "")
        fn = part.get_filename()
        if fn or "attachment" in cd.lower():
            out.append((fn or "", part.get_payload(decode=True) or b""))
    return out


def body_text(m):
    for part in m.walk():
        if part.is_multipart():
            continue
        cd = str(part.get("Content-Disposition") or "")
        if part.get_content_type() == "text/plain" and "attachment" not in cd.lower():
            return (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
    return ""


def email_field(b, snake):
    m = email_msg(b)
    s = snake.lower()
    if s in ("attachment_filenames", "attachment_names", "attachments"):
        return cj([fn for fn, _ in attachments(m)])
    if s in ("attachment_filename", "attachment_name"):
        a = attachments(m); return a[0][0] if a else "none"
    if s == "attachment_count":
        return str(len(attachments(m)))
    mo = re.fullmatch(r"attachment_(sha256|sha1|md5|size_bytes|size)", s)
    if mo:
        a = attachments(m)
        if not a: return "none"
        d = a[0][1]
        return str(len(d)) if mo.group(1).startswith("size") else getattr(hashlib, mo.group(1))(d).hexdigest()
    if s in ("body_text", "body"):
        return body_text(m).strip()
    if s in ("correlation_token", "token"):
        mo = re.search(r"Correlation token:\s*(\S+)", body_text(m))
        return mo.group(1) if mo else (unfold(m.get("X-Huntress-Correlation")) if m.get("X-Huntress-Correlation") else "none")
    if s == "boundary":
        return m.get_boundary() or "none"
    if s in ("header_count", "headers_count"):
        return str(len(m.keys()))
    if s in ("header_names", "headers"):
        return cj(list(m.keys()))
    key = EMAIL_ALIASES.get(s)
    if key is None:
        w = s.replace("_", "")
        for h in m.keys():
            if h.replace("-", "").replace("_", "").lower() == w:
                key = h; break
    if key is None:
        raise KeyError("no email field %s (headers %s)" % (snake, list(m.keys())))
    vals = m.get_all(key)
    if not vals:
        return "none"
    return unfold(vals[0])


def field_value(fld, b):
    mo = re.fullmatch(r"email\.(\w+)", fld or "")
    if mo:
        return email_field(b, mo.group(1))
    return m15._field_value_orig(fld, b)


m15._field_value_orig = m15.field_value
m15.field_value = field_value


def fix_json_kind(st, sub):
    """answer ids whose answer_format.kind is json but value is not valid JSON -> compact array of whitespace tokens."""
    kinds = {}
    for q in st["questions"]:
        k = (q.get("answer_format") or {}).get("kind")
        kinds[q["id"]] = k
        for s in ("set%s.%s" % (q.get("set"), q["id"]),):
            kinds[s] = k
    for k, v in list(sub.items()):
        if kinds.get(k) == "json":
            try:
                json.loads(v)
            except Exception:
                sub[k] = cj(v.split())
    return sub


if __name__ == "__main__":
    from gmx import GMX
    ch = sys.argv[1]
    op = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith("--") else "start"
    t0 = time.time()
    g = GMX()
    if "--dir" in sys.argv:
        dd = sys.argv[sys.argv.index("--dir") + 1]
        st = json.load(open(os.path.join(dd, "start.json")))
        raws = [open(os.path.join(dd, f), "rb").read() for f in sorted(os.listdir(dd)) if f.startswith("artifact")]
    else:
        st = g.post({"op": op, "challenge": ch}) if op != "none" else g.status(ch)
        if not st.get("answer_ids"):
            print("NO ATTEMPT", {k: v for k, v in st.items() if k != "guidance"}); sys.exit(1)
        raws = [g.artifact(ch)]
        if "--save" in sys.argv:
            sd = sys.argv[sys.argv.index("--save") + 1]; os.makedirs(sd, exist_ok=True)
            json.dump(st, open(os.path.join(sd, "start.json"), "w"))
            open(os.path.join(sd, "artifact.bin"), "wb").write(raws[0])
    print("mode", st.get("mode"), "deadline", st.get("deadline"), "uar", st.get("unique_attempts_remaining"),
          "nq", len(st["questions"]), "nids", len(st.get("answer_ids") or []))
    files = []
    for r in raws:
        files += unzip_all(r)
    ans, unk = solve(st, files)
    nsets = len({q.get("set") for q in st["questions"]})
    if "--dir" not in sys.argv and any(len(u) == 2 and str(u[1]).startswith("NOFILE") for u in unk):
        for d in range(1, max(nsets, 2)):
            try:
                files += unzip_all(g.artifact(ch, d))
            except Exception as ex:
                print("delivery", d, "ERR", ex)
        ans, unk = solve(st, files)
    sub = fix_json_kind(st, map_ids(st, ans))
    print("computed %d/%d in %.2fs; unknown %d" % (len(sub), len(st.get("answer_ids") or []), time.time() - t0, len(unk)))
    if "--submit" in sys.argv and sub:
        r = g.submit(ch, sub)
        print("SUBMIT", len(sub), {k: r.get(k) for k in ("result", "flag", "error", "remaining")}, "%.2fs" % (time.time() - t0))
    for k, v in list(sub.items())[:400]:
        print("  %-70s %r" % (k, v))
    for u in unk:
        print("  UNK", u)
