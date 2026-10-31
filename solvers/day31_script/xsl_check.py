"""usage: xsl_check.py <dir of .xsl files>
Independent check of the sdec decode for XSLT carriers: pulls the comment + <descriptor> payloads with a
plain regex (nothing is applied or transformed), reports whether the two copies agree, the structure of the
stylesheet around them, and the decoded descriptor from the shared solver."""
import sys, os, re, collections
sys.path.insert(0, "~/d31/tools")
from sdec import decode_specimen

d = sys.argv[1]
hdrs = collections.Counter()
for f in sorted(os.listdir(d)):
    if not f.endswith(".xsl"):
        continue
    t = open(os.path.join(d, f), "rb").read().decode("utf-8-sig", "replace")
    m = re.search(r"HUNTRESS_ANALYSIS_V1:([A-Z0-9_]+)-(\S+)", t)
    hdr, pay = (m.group(1), m.group(2)) if m else (None, None)
    hdrs[hdr] += 1
    tags = sorted(set(re.findall(r"<([A-Za-z_:][\w:.-]*)", t)))
    body = re.search(r"<descriptor>(.*?)</descriptor>", t, re.S)
    b = body.group(1) if body else None
    rest = re.sub(r"<!--.*?-->", "", t, flags=re.S)
    rest = re.sub(r"\b[0-9a-zA-Z+/=_-]{60,}\b", "<BLOB>", rest)
    dec = decode_specimen(f, t)
    print("=" * 8, f, "hdr", hdr, "paylen", len(pay or ""), "body==comment", b == pay, "tags", tags)
    print(rest[:700])
    print("DEC keys", sorted(dec))
    print("DESC", {k: v for k, v in dec.items() if k not in ("plan",)} if not dec.get("plan") else dec.get("plan"))
print(hdrs)
